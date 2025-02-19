from http import HTTPStatus

from django.utils.decorators import method_decorator

from allauth.account import app_settings as account_settings
from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.internal import flows
from allauth.account.internal.flows import (
    email_verification,
    manage_email,
    password_change,
    password_reset,
    password_reset_by_code,
)
from allauth.account.stages import EmailVerificationStage, LoginStageController
from allauth.account.utils import send_email_confirmation
from allauth.core import ratelimit
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.decorators import rate_limit
from allauth.headless.account import response
from allauth.headless.account.inputs import (
    AddEmailInput,
    ChangePasswordInput,
    ConfirmLoginCodeInput,
    DeleteEmailInput,
    LoginInput,
    MarkAsPrimaryEmailInput,
    ReauthenticateInput,
    RequestLoginCodeInput,
    RequestPasswordResetInput,
    ResetPasswordInput,
    ResetPasswordKeyInput,
    SelectEmailInput,
    SignupInput,
    VerifyEmailInput,
)
from allauth.headless.base.response import (
    APIResponse,
    AuthenticationResponse,
    ConflictResponse,
    ForbiddenResponse,
)
from allauth.headless.base.views import APIView, AuthenticatedAPIView
from allauth.headless.internal import authkit
from allauth.headless.internal.restkit.response import ErrorResponse


class RequestLoginCodeView(APIView):
    input_class = RequestLoginCodeInput

    def post(self, request, *args, **kwargs):
        flows.login_by_code.LoginCodeVerificationProcess.initiate(
            request=self.request,
            user=self.input._user,
            email=self.input.cleaned_data["email"],
        )
        return AuthenticationResponse(self.request)


class ConfirmLoginCodeView(APIView):
    input_class = ConfirmLoginCodeInput

    def dispatch(self, request, *args, **kwargs):
        auth_status = authkit.AuthenticationStatus(request)
        self.stage = auth_status.get_pending_stage()
        if not self.stage:
            return ConflictResponse(request)
        self.process = flows.login_by_code.LoginCodeVerificationProcess.resume(
            self.stage
        )
        if not self.process:
            return ConflictResponse(request)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        response = self.process.finish(None)
        return AuthenticationResponse.from_response(request, response)

    def get_input_kwargs(self):
        kwargs = super().get_input_kwargs()
        kwargs["code"] = self.process.code
        return kwargs

    def handle_invalid_input(self, input):
        self.process.record_invalid_attempt()
        return super().handle_invalid_input(input)


@method_decorator(rate_limit(action="login"), name="handle")
class LoginView(APIView):
    input_class = LoginInput

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return ConflictResponse(request)
        credentials = self.input.cleaned_data
        response = flows.login.perform_password_login(
            request, credentials, self.input.login
        )
        return AuthenticationResponse.from_response(request, response)


@method_decorator(rate_limit(action="signup"), name="handle")
class SignupView(APIView):
    input_class = {"POST": SignupInput}
    by_passkey = False

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return ConflictResponse(request)
        if not get_account_adapter().is_open_for_signup(request):
            return ForbiddenResponse(request)
        user, resp = self.input.try_save(request)
        if not resp:
            try:
                resp = flows.signup.complete_signup(
                    request, user=user, by_passkey=self.by_passkey
                )
            except ImmediateHttpResponse:
                pass
        return AuthenticationResponse.from_response(request, resp)


class SessionView(APIView):
    def get(self, request, *args, **kwargs):
        return AuthenticationResponse(request)

    def delete(self, request, *args, **kwargs):
        adapter = get_account_adapter()
        adapter.logout(request)
        return AuthenticationResponse(request)


class VerifyEmailView(APIView):
    input_class = VerifyEmailInput

    def handle(self, request, *args, **kwargs):
        self.stage = LoginStageController.enter(request, EmailVerificationStage.key)
        if (
            not self.stage
            and account_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED
            and not request.user.is_authenticated
        ):
            return ConflictResponse(request)
        return super().handle(request, *args, **kwargs)

    def handle_invalid_input(self, input: VerifyEmailInput):
        self._record_invalid_attempt()
        return super().handle_invalid_input(input)

    def _record_invalid_attempt(self) -> None:
        if account_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED:
            _, pending_verification = (
                flows.email_verification_by_code.get_pending_verification(
                    self.request, peek=True
                )
            )
            if pending_verification:
                flows.email_verification_by_code.record_invalid_attempt(
                    self.request, pending_verification
                )

    def get(self, request, *args, **kwargs):
        key = request.headers.get("x-email-verification-key", "")
        input = self.input_class({"key": key})
        if not input.is_valid():
            self._record_invalid_attempt()
            return ErrorResponse(request, input=input)
        verification = input.cleaned_data["key"]
        return response.VerifyEmailResponse(request, verification, stage=self.stage)

    def post(self, request, *args, **kwargs):
        verification = self.input.cleaned_data["key"]
        email_address = verification.confirm(request)
        if not email_address:
            # Should not happen, VerifyInputInput should have verified all
            # preconditions.
            return APIResponse(request, status=HTTPStatus.INTERNAL_SERVER_ERROR)
        response = None
        if self.stage:
            # Verifying email as part of login/signup flow may imply the user is
            # to be logged in...
            response = email_verification.login_on_verification(request, verification)
        return AuthenticationResponse.from_response(request, response)


class RequestPasswordResetView(APIView):
    input_class = RequestPasswordResetInput

    def post(self, request, *args, **kwargs):
        r429 = ratelimit.consume_or_429(
            self.request,
            action="reset_password",
            key=self.input.cleaned_data["email"].lower(),
        )
        if r429:
            return r429
        self.input.save(request)
        if account_settings.PASSWORD_RESET_BY_CODE_ENABLED:
            return AuthenticationResponse(request)
        return response.RequestPasswordResponse(request)


@method_decorator(rate_limit(action="reset_password_from_key"), name="handle")
class ResetPasswordView(APIView):
    input_class = ResetPasswordInput

    def handle_invalid_input(self, input: ResetPasswordInput):
        if self.process and "key" in input.errors:
            self.process.record_invalid_attempt()
        return super().handle_invalid_input(input)

    def handle(self, request, *args, **kwargs):
        self.process = None
        if account_settings.PASSWORD_RESET_BY_CODE_ENABLED:
            self.process = (
                password_reset_by_code.PasswordResetVerificationProcess.resume(
                    self.request
                )
            )
            if not self.process:
                return ConflictResponse(request)
        return super().handle(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        key = request.headers.get("X-Password-Reset-Key", "")
        if self.process:
            input = ResetPasswordKeyInput({"key": key}, code=self.process.code)
            if not input.is_valid():
                self.process.record_invalid_attempt()
                return ErrorResponse(request, input=input)
            self.process.confirm_code()
            return response.PasswordResetKeyResponse(request, self.process.user)
        else:
            input = ResetPasswordKeyInput({"key": key})
            if not input.is_valid():
                return ErrorResponse(request, input=input)
            return response.PasswordResetKeyResponse(request, input.user)

    def get_input_kwargs(self):
        ret = {}
        if self.process:
            ret.update({"code": self.process.code, "user": self.process.user})
        return ret

    def post(self, request, *args, **kwargs):
        user = self.input.user
        flows.password_reset.reset_password(user, self.input.cleaned_data["password"])
        if self.process:
            self.process.confirm_code()
            self.process.finish()
        else:
            password_reset.finalize_password_reset(request, user)
        return AuthenticationResponse(self.request)


@method_decorator(rate_limit(action="change_password"), name="handle")
class ChangePasswordView(AuthenticatedAPIView):
    input_class = ChangePasswordInput

    def post(self, request, *args, **kwargs):
        password_change.change_password(
            self.request.user, self.input.cleaned_data["new_password"]
        )
        is_set = not self.input.cleaned_data.get("current_password")
        if is_set:
            password_change.finalize_password_set(request, request.user)
        else:
            password_change.finalize_password_change(request, request.user)
        return AuthenticationResponse(request)

    def get_input_kwargs(self):
        return {"user": self.request.user}


@method_decorator(rate_limit(action="manage_email"), name="handle")
class ManageEmailView(AuthenticatedAPIView):
    input_class = {
        "POST": AddEmailInput,
        "PUT": SelectEmailInput,
        "DELETE": DeleteEmailInput,
        "PATCH": MarkAsPrimaryEmailInput,
    }

    def get(self, request, *args, **kwargs):
        return self._respond_email_list()

    def _respond_email_list(self):
        addrs = manage_email.list_email_addresses(self.request, self.request.user)
        return response.EmailAddressesResponse(self.request, addrs)

    def post(self, request, *args, **kwargs):
        flows.manage_email.add_email(request, self.input)
        return self._respond_email_list()

    def delete(self, request, *args, **kwargs):
        addr = self.input.cleaned_data["email"]
        flows.manage_email.delete_email(request, addr)
        return self._respond_email_list()

    def patch(self, request, *args, **kwargs):
        addr = self.input.cleaned_data["email"]
        flows.manage_email.mark_as_primary(request, addr)
        return self._respond_email_list()

    def put(self, request, *args, **kwargs):
        addr = self.input.cleaned_data["email"]
        sent = send_email_confirmation(request, request.user, email=addr.email)
        return response.RequestEmailVerificationResponse(
            request, verification_sent=sent
        )

    def get_input_kwargs(self):
        return {"user": self.request.user}


@method_decorator(rate_limit(action="reauthenticate"), name="handle")
class ReauthenticateView(AuthenticatedAPIView):
    input_class = ReauthenticateInput

    def post(self, request, *args, **kwargs):
        flows.reauthentication.reauthenticate_by_password(self.request)
        return AuthenticationResponse(self.request)

    def get_input_kwargs(self):
        return {"user": self.request.user}

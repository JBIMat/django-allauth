from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.management.utils import get_random_secret_key
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from allauth.account.internal.userkit import (
    str_to_user_id,
    user_id_to_str,
    user_username,
)
from allauth.account.models import EmailAddress
from allauth.core.internal.adapter import BaseAdapter
from allauth.core.internal.cryptokit import generate_user_code
from allauth.idp.oidc import app_settings
from allauth.utils import import_attribute


if TYPE_CHECKING:
    from allauth.idp.oidc.models import Client, Token


class DefaultOIDCAdapter(BaseAdapter):
    """The adapter class allows you to override various functionality of the
    ``allauth.idp.oidc`` app.  To do so, point ``settings.IDP_OIDC_ADAPTER`` to
    your own class that derives from ``DefaultOIDCAdapter`` and override the
    behavior by altering the implementation of the methods according to your own
    needs.
    """

    scope_display = {
        "openid": _("View your user ID"),
        "email": _("View your email address"),
        "profile": _("View your basic profile information"),
    }

    def generate_client_id(self) -> str:
        """
        The client ID to use for newly created clients.
        """
        return uuid.uuid4().hex

    def generate_client_secret(self) -> str:
        """
        The client secret to use for newly created clients.
        """
        return get_random_secret_key()

    def generate_user_code(self) -> str:
        return generate_user_code(**app_settings.USER_CODE_FORMAT)

    def hash_token(self, token: str) -> str:
        """
        We don't store tokens directly, only the hash of the token. This methods generates
        that hash.
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def get_issuer(self) -> str:
        """
        Returns the URL of the issuer.
        """
        return self.request.build_absolute_uri("/").rstrip("/")

    def populate_id_token(
        self,
        id_token: dict[str, Any],
        client: Client,
        scopes: Iterable[str],
        **kwargs: Any,
    ) -> None:
        """
        This method can be used to alter the ID token payload. It is already populated
        with basic values. Depending on the client and requested scopes, you can
        expose additional information here.
        """
        pass

    def populate_access_token(
        self,
        access_token: dict[str, Any],
        *,
        client: Client,
        scopes: Iterable[str],
        user: AbstractBaseUser,
        **kwargs: Any,
    ) -> None:
        """
        This method can be used to alter the JWT access token payload. It is already
        populated with basic values.
        """
        pass

    def get_claims(
        self,
        purpose: Literal["id_token", "userinfo"],
        user: AbstractBaseUser,
        client: Client,
        scopes: Iterable[str],
        email: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Return the claims to be included in the ID token or userinfo response.
        """
        claims: dict[str, Any] = {"sub": self.get_user_sub(client, user)}
        if "email" in scopes:
            address: EmailAddress | None = None
            if email:
                try:
                    address = EmailAddress.objects.get_for_user(user, email)
                except EmailAddress.DoesNotExist:
                    pass
            else:
                address = EmailAddress.objects.get_primary(user)
            if address:
                claims.update(
                    {
                        "email": address.email,
                        "email_verified": address.verified,
                    }
                )
        if "profile" in scopes:
            if hasattr(user, "get_full_name"):
                full_name = user.get_full_name()
            else:
                full_name = ""
            last_name = getattr(user, "last_name", None)
            first_name = getattr(user, "first_name", None)
            username = user_username(user)
            profile_claims = {
                "name": full_name,
                "given_name": first_name,
                "family_name": last_name,
                "preferred_username": username,
            }
            for claim_key, claim_value in profile_claims.items():
                if claim_value:
                    claims[claim_key] = claim_value
        return claims

    def get_user_sub(self, client: Client, user: AbstractBaseUser) -> str:
        """
        Returns the "sub" (subject identifier) for the given user.
        """
        return user_id_to_str(user)

    def get_user_by_sub(self, client: Client, sub: str) -> AbstractBaseUser | None:
        """
        Looks up a user, given its subject identifier. Returns `None` if no
        such user was found.
        """
        try:
            pk = str_to_user_id(sub)
        except ValueError:
            return None
        user = get_user_model().objects.filter(pk=pk).first()
        if not user or not user.is_active:
            return None
        return user

    def validate_client_registration(
        self,
        *,
        client: Client,
        client_metadata: dict[str, Any],
        token: Token | None,
        bearer_token: str | None,
        **kwargs: Any,
    ) -> None:
        """
        This method is called after all builtin validation was successful,
        and just before the actual client is being created. To intervene, raise
        a ``ValidationError`` or an ``ImmediateHttpResponse``.

        ``client``: The ``Client`` instance that is about to be saved.
        ``client_metadata``: The raw JSON payload from the DCR request.
        ``token``: The ``Token`` instance corresponding to the initial access
            token, or ``None`` if no token was provided.
        ``bearer_token``: The raw bearer token string from the ``Authorization``
            header, or ``None`` if no token was provided.
        """
        pass

    def validate_resource_uris(self, *, uris: list[str], **kwargs: Any) -> None:
        """
        Allows for custom validation of resource URIs (RFC 8707).
        Throw a ``ValidationError`` to reject the resource.
        """
        pass

    def populate_server_metadata(self, data: dict[str, str | list[str]]) -> None:
        """
        Allows for customizing the ``/.well-known/openid-configuration``
        payload, as specified in `RFC 8414`_ (OAuth 2.0 Authorization Server
        Metadata).

        .. _RFC 8414: https://www.rfc-editor.org/info/rfc8414
        """
        pass

    def is_cimd_url_allowed(self, url: str) -> bool:
        """
        Determines whether the given CIMD (Client ID Metadata Document) URL is
        accepted as a ``client_id``.

        Override this method to restrict which clients can authenticate via CIMD,
        for example by maintaining a domain allowlist.  The default implementation
        accepts all URLs that pass structural validation.
        """
        return True

    def get_current_private_key(self) -> str:
        """
        Returns the private key used for signing JWTs. The default implementation returns the value of the ``IDP_OIDC_PRIVATE_KEY`` setting.
        Override this method to provide a different key, for example if a secret manager / vault is used.
        """
        return app_settings.PRIVATE_KEY

    def get_jwks_cache_control(self) -> int:
        """
        Returns the cache control value for the JWKS endpoint. The default implementation returns the value of the ``IDP_OIDC_JWKS_CACHE_CONTROL`` setting.
        Override this method to provide a different cache control value, e.g. in case of a secret manager / vault is used.
        """
        if isinstance(app_settings.DECOMMISSION_PREVIOUS_KEY_AT, datetime) and timezone.now() < app_settings.DECOMMISSION_PREVIOUS_KEY_AT:
            return int(app_settings.DECOMMISSION_PREVIOUS_KEY_AT.timestamp() - timezone.now().timestamp())
        return app_settings.JWKS_CACHE_CONTROL

    def get_private_keys(self) -> list[str]:
        """
        Returns a list of all private keys available. The default implementation returns a list containing the current private key,
        and if an old private key is configured and not yet decommissioned, it is included as well.

        If you want to access the active private key, use ``get_current_private_key()``.
        This method is used for token verification, and should return all keys that might have been used for signing tokens that are still valid.
        """
        keys = [self.get_current_private_key()]
        if app_settings.PREVIOUS_PRIVATE_KEY and (not isinstance(app_settings.DECOMMISSION_PREVIOUS_KEY_AT, datetime) or timezone.now() < app_settings.DECOMMISSION_PREVIOUS_KEY_AT):
            keys.append(app_settings.PREVIOUS_PRIVATE_KEY)
        return keys


def get_adapter() -> DefaultOIDCAdapter:
    return import_attribute(app_settings.ADAPTER)()

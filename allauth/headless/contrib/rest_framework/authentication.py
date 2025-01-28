from django.http import HttpRequest

from rest_framework import authentication

from allauth.headless.internal.sessionkit import (
    authenticate_by_x_session_token,
)


class XSessionTokenAuthentication(authentication.BaseAuthentication):
    """
    This authentication class uses the X-Session-Token that django-allauth
    is using for authentication purposes.
    """

    def authenticate(self, request: HttpRequest):
        token = request.headers.get("X-Session-Token")
        if token:
            return authenticate_by_x_session_token(token)
        return None

from http import HTTPStatus

from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.http import urlencode

import pytest

from allauth.idp.oidc.internal.clientkit import clean_post_logout_redirect_uri
from allauth.idp.oidc.models import Client, Token


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "with_client,post_logout_redirect_uri,state,expected_location",
    [
        (False, None, None, "/"),
        (True, None, None, "/"),
        (False, "https://rp.client/logged-out", None, "/"),
        (True, "https://rp.client/logged-out", None, "https://rp.client/logged-out"),
        (True, "https://evil.client/logged-out", None, None),
        (
            True,
            "https://rp.client/logged-out",
            "mystate",
            "https://rp.client/logged-out?state=mystate",
        ),
        (True, "http://no-http.org/please", None, None),
    ],
)
def test_logout_while_anonymous(
    method,
    client,
    with_client,
    oidc_client,
    post_logout_redirect_uri,
    state,
    expected_location,
):
    params = {}
    if with_client:
        params["client_id"] = oidc_client.pk
    if post_logout_redirect_uri:
        params["post_logout_redirect_uri"] = post_logout_redirect_uri
    if state:
        params["state"] = state
    if method == "GET":
        query = None
        if params:
            query = urlencode(params)
        resp = client.get(reverse("idp:oidc:logout") + (f"?{query}" if query else ""))
    else:
        resp = client.post(reverse("idp:oidc:logout"), data=params)
    if expected_location is None:
        assert resp.status_code == HTTPStatus.OK
        assert resp.context["error_form"].errors["post_logout_redirect_uri"] == [
            "Enter a valid URL."
        ]
    else:
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == expected_location


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_logout_must_ask(auth_client, settings, method):
    settings.IDP_OIDC_RP_INITIATED_LOGOUT_ASKS_FOR_OP_LOGOUT = False
    params = {}
    if method == "GET":
        query = None
        if params:
            query = urlencode(params)
        resp = auth_client.get(
            reverse("idp:oidc:logout") + (f"?{query}" if query else "")
        )
    else:
        resp = auth_client.post(reverse("idp:oidc:logout"), data=params)
    assert resp.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "csrfmiddlewaretoken, status_code",
    [(None, HTTPStatus.OK), ("", HTTPStatus.FORBIDDEN), ("hack", HTTPStatus.FORBIDDEN)],
)
def test_rp_cannot_bypass(auth_client, csrfmiddlewaretoken, status_code):
    auth_client.enforce_csrf_checks = True
    auth_client.handler.enforce_csrf_checks = True
    params = {
        # Try a POST that answers the question right away...
        "action": "logout",
    }
    if csrfmiddlewaretoken is not None:
        params["csrfmiddlewaretoken"] = "hack"
    resp = auth_client.post(reverse("idp:oidc:logout"), data=params)
    assert resp.status_code == status_code


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_logout_without_asking(
    auth_client,
    user,
    settings,
    method,
    oidc_client,
    id_token_factory,
    access_token_factory,
    refresh_token_factory,
):
    id_token_hint = id_token_factory(oidc_client, user)
    access_token, access_token_instance = access_token_factory(oidc_client, user)
    refresh_token, refresh_token_instance = refresh_token_factory(
        user=user, client=oidc_client
    )
    settings.IDP_OIDC_RP_INITIATED_LOGOUT_ASKS_FOR_OP_LOGOUT = False
    params = {
        "id_token_hint": id_token_hint,
        "post_logout_redirect_uri": "https://rp.client/logged-out",
        "client_id": oidc_client.pk,
    }
    if method == "GET":
        query = None
        if params:
            query = urlencode(params)
        resp = auth_client.get(
            reverse("idp:oidc:logout") + (f"?{query}" if query else "")
        )
    else:
        resp = auth_client.post(reverse("idp:oidc:logout"), data=params)
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == "https://rp.client/logged-out"

    assert not Token.objects.filter(pk=access_token_instance.pk).exists()
    assert not Token.objects.filter(pk=refresh_token_instance.pk).exists()
    resp = auth_client.get(reverse("account_email"))
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"].startswith(reverse("account_login"))


@pytest.mark.parametrize(
    "logout_url,valid",
    [
        # Invalid https URL
        ("https://org.allauth.app://logout", False),
        # Scheme matches one of the redirect URIs
        ("org.allauth.app://logout", True),
        # Unknown scheme
        ("com.allauth.app://logout", False),
    ],
)
def test_app_logout_redirect_uri(client, oidc_client, logout_url, valid):
    oidc_client.set_redirect_uris(["org.allauth.app://callback"])
    oidc_client.save()
    params = {
        "client_id": oidc_client.pk,
        "post_logout_redirect_uri": logout_url,
    }
    query = urlencode(params)
    resp = client.get(reverse("idp:oidc:logout") + (f"?{query}" if query else ""))
    if valid:
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == logout_url
    else:
        assert resp.status_code == HTTPStatus.OK
        assert resp.context["error_form"].errors["post_logout_redirect_uri"] == [
            "Enter a valid URL."
        ]


@pytest.mark.parametrize(
    "is_valid,post_logout_redirect_uri,post_logout_redirect_uris",
    [
        # Exact match.
        (True, "https://rp.client/logout", ["https://rp.client/logout"]),
        # Matches one of several registered entries.
        (
            True,
            "https://rp.client/logout",
            ["https://other.example/x", "https://rp.client/logout"],
        ),
        # Same origin, but a different path than registered -> rejected.
        (None, "https://rp.client/logged-out", ["https://rp.client/logout"]),
        # Different host -> rejected.
        (None, "https://evil.client/logout", ["https://rp.client/logout"]),
        # Registered query is a subset of the requested one -> allowed.
        (
            True,
            "https://rp.client/logout?foo=1&bar=2",
            ["https://rp.client/logout?foo=1"],
        ),
        # Registered query is not a subset -> rejected.
        (
            None,
            "https://rp.client/logout?foo=1",
            ["https://rp.client/logout?foo=1&bar=2"],
        ),
        # A native application scheme registered explicitly is honored.
        (True, "org.allauth.app://logout", ["org.allauth.app://logout"]),
        # -- No explicit post_logout_redirect_uris: fall back to matching the
        #    scheme/host/port against the registered redirect_uris.
        # Origin matches a redirect URI; the path is irrelevant.
        (True, "https://rp.client/logged-out", []),
        (True, "https://rp.client/any/path?x=1", []),
        # Origin is not among the redirect URIs -> rejected.
        (None, "https://evil.client/logged-out", []),
        # http passes the scheme check (the client is confidential), but the
        # redirect URIs are https, so the origin does not match -> rejected.
        (None, "http://rp.client/logged-out", []),
        # -- Scheme handling.
        # Scheme not used by any registered URI -> rejected.
        (None, "ftp://rp.client/logout", []),
        # Unregistered native application scheme -> rejected.
        (None, "org.allauth.app://logout", []),
        # -- Malformed / empty.
        # Allowed scheme, but not a valid URL -> rejected.
        (None, "https://", []),
        # No URI supplied -> nothing to honor, no error.
        (False, None, []),
    ],
)
def test_clean_post_logout_redirect_uri(
    oidc_client: Client,
    is_valid: bool | None,
    post_logout_redirect_uri: str | None,
    post_logout_redirect_uris: list[str],
):
    oidc_client.set_post_logout_redirect_uris(post_logout_redirect_uris)
    try:
        ret = clean_post_logout_redirect_uri(post_logout_redirect_uri, oidc_client)
        if is_valid:
            assert post_logout_redirect_uri == ret
        elif is_valid is False:
            assert ret is None
        else:
            assert False, "ValidationError expected"
    except ValidationError:
        if is_valid is not None:
            assert False, "ValidationError unexpected"


@pytest.mark.parametrize("with_id_token_hint", [False, True])
def test_client_id_derived_from_id_token_hint(
    auth_client,
    user,
    settings,
    oidc_client,
    id_token_factory,
    with_id_token_hint,
):
    settings.IDP_OIDC_RP_INITIATED_LOGOUT_ASKS_FOR_OP_LOGOUT = False
    id_token_hint = id_token_factory(oidc_client, user)
    params = {
        "post_logout_redirect_uri": "https://rp.client/logged-out",
    }
    if with_id_token_hint:
        params["id_token_hint"] = id_token_hint
    resp = auth_client.post(reverse("idp:oidc:logout"), data=params)
    if with_id_token_hint:
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == "https://rp.client/logged-out"
    else:
        assert resp.status_code == HTTPStatus.OK

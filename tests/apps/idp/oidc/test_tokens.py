from datetime import timedelta
from http import HTTPStatus
from unittest.mock import ANY

from django.urls import reverse
from django.utils import timezone

import pytest

from allauth.idp.oidc.models import Token


def test_userinfo_bad_token(client, oidc_client, user):
    # Pass along ID token as hint
    resp = client.get(reverse("idp:oidc:userinfo"))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json() == {
        "error": "invalid_token",
        "error_description": "The access token provided is expired, revoked, malformed, or invalid for other reasons.",
    }


def test_revoke_access_token(
    client, oidc_client, oidc_client_secret, user, access_token_generator
):
    token, instance = access_token_generator(oidc_client, user)
    _, instance_to_keep = access_token_generator(oidc_client, user)
    resp = client.post(
        reverse("idp:oidc:revoke"),
        data={
            "client_id": oidc_client.id,
            "client_secret": oidc_client_secret,
            "token": token,
        },
    )
    assert resp.status_code == HTTPStatus.OK
    assert not Token.objects.filter(pk=instance.pk).exists()
    assert Token.objects.filter(pk=instance_to_keep.pk).exists()


@pytest.mark.parametrize(
    "resources",
    [
        [],
        ["https://api.example.com/a"],
        ["https://api.example.com/a", "https://api.example.com/b"],
    ],
)
@pytest.mark.parametrize("rotate_refresh_token", [False, True])
@pytest.mark.parametrize("scopes", [("openid",), ("openid", "email")])
def test_refresh_token(
    db,
    client,
    oidc_client,
    oidc_client_secret,
    user,
    refresh_token_factory,
    settings,
    rotate_refresh_token,
    scopes,
    resources,
):
    settings.IDP_OIDC_ROTATE_REFRESH_TOKEN = rotate_refresh_token
    rt, rt_instance = refresh_token_factory(
        user=user, client=oidc_client, scopes=scopes
    )
    rt_instance.set_scope_email("a@b.org")
    rt_instance.save()
    data = {
        "refresh_token": rt,
        "grant_type": "refresh_token",
        "client_id": oidc_client.id,
        "client_secret": oidc_client_secret,
    }
    if resources:
        data["resource"] = resources
    resp = client.post(reverse("idp:oidc:token"), data)

    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    new_rt_instance = Token.objects.lookup(
        Token.Type.REFRESH_TOKEN, data["refresh_token"]
    )
    if rotate_refresh_token:
        assert data["refresh_token"] != rt
        assert new_rt_instance.pk != rt_instance.pk
    else:
        assert data["refresh_token"] == rt
    assert Token.objects.filter(type=Token.Type.REFRESH_TOKEN).count() == 1
    token = Token.objects.lookup(Token.Type.ACCESS_TOKEN, data["access_token"])
    assert set(token.get_resources()) == set(resources)
    assert token.get_scope_email() == ("a@b.org" if "email" in scopes else None)
    return
    assert data == {
        "access_token": ANY,
        "expires_in": 3600,
        "refresh_token": ANY,
        "scope": "openid profile",
        "token_type": "Bearer",
    }


@pytest.mark.parametrize(
    "refresh_token_expires_in,expect_expiry",
    [
        (None, False),
        (3600, True),
    ],
)
def test_refresh_token_expiry(
    db,
    client,
    oidc_client,
    oidc_client_secret,
    user,
    refresh_token_factory,
    settings,
    refresh_token_expires_in,
    expect_expiry,
):
    settings.IDP_OIDC_ROTATE_REFRESH_TOKEN = True
    settings.IDP_OIDC_REFRESH_TOKEN_EXPIRES_IN = refresh_token_expires_in
    rt, rt_instance = refresh_token_factory(user=user, client=oidc_client)
    resp = client.post(
        reverse("idp:oidc:token"),
        {
            "refresh_token": rt,
            "grant_type": "refresh_token",
            "client_id": oidc_client.id,
            "client_secret": oidc_client_secret,
        },
    )
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    new_rt = Token.objects.lookup(Token.Type.REFRESH_TOKEN, data["refresh_token"])
    if expect_expiry:
        assert new_rt.expires_at is not None
        expected = timezone.now() + timedelta(seconds=refresh_token_expires_in)
        assert abs((new_rt.expires_at - expected).total_seconds()) < 30
    else:
        assert new_rt.expires_at is None


def test_refresh_token_expired(
    db, client, oidc_client, oidc_client_secret, user, refresh_token_factory
):
    rt, rt_instance = refresh_token_factory(user=user, client=oidc_client)
    rt_instance.expires_at = timezone.now() - timedelta(seconds=1)
    rt_instance.save()
    resp = client.post(
        reverse("idp:oidc:token"),
        {
            "refresh_token": rt,
            "grant_type": "refresh_token",
            "client_id": oidc_client.id,
            "client_secret": oidc_client_secret,
        },
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json()["error"] == "invalid_grant"


def test_revoke_refresh_token(
    db, client, oidc_client, oidc_client_secret, user, refresh_token_factory
):
    token_value, token_instance = refresh_token_factory(user=user, client=oidc_client)
    resp = client.post(
        reverse("idp:oidc:revoke"),
        {
            "token": token_value,
            "client_id": oidc_client.id,
            "client_secret": oidc_client_secret,
        },
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.content == b""
    assert not Token.objects.filter(pk=token_instance.pk).exists()


@pytest.mark.parametrize(
    "auth_resources,token_resources,success",
    [
        ([], ["https://api.example.com/a"], True),
        (["https://api.example.com"], ["https://api.example.com/a"], True),
        (["https://api.example.org"], ["https://api.example.com/a"], False),
        (
            ["https://api.example.org", "https://api.example.com"],
            ["https://api.example.com/a"],
            True,
        ),
        (["https://api.example.com/a"], ["https://api.example.com/b"], False),
    ],
)
def test_refresh_resource_vs_subresource(
    db,
    client,
    oidc_client,
    oidc_client_secret,
    user,
    refresh_token_factory,
    settings,
    auth_resources,
    token_resources,
    success,
):
    scopes = ["openid"]
    rt, rt_instance = refresh_token_factory(
        user=user, client=oidc_client, scopes=scopes
    )
    rt_instance.set_scope_email("a@b.org")
    rt_instance.set_resources(auth_resources)
    rt_instance.save()
    data = {
        "refresh_token": rt,
        "grant_type": "refresh_token",
        "client_id": oidc_client.id,
        "client_secret": oidc_client_secret,
    }
    if token_resources:
        data["resource"] = token_resources
    resp = client.post(reverse("idp:oidc:token"), data)

    if success:
        assert resp.status_code == HTTPStatus.OK
        data = resp.json()
        refresh_token = Token.objects.lookup(
            Token.Type.REFRESH_TOKEN, data["refresh_token"]
        )
        access_token = Token.objects.lookup(
            Token.Type.ACCESS_TOKEN, data["access_token"]
        )
        assert set(refresh_token.get_resources()) == set(auth_resources)
        assert set(access_token.get_resources()) == set(token_resources)
    else:
        assert resp.status_code == HTTPStatus.BAD_REQUEST
        data = resp.json()
        assert data == {
            "error": "invalid_target",
            "error_description": "The requested resource is invalid, missing, unknown, or malformed.",
        }

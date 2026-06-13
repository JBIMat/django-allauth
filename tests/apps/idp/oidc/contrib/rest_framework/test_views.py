from http import HTTPStatus

from django.urls import reverse

import pytest


def test_resource(db, client, access_token_factory, user, oidc_client):
    token, _ = access_token_factory(
        client=oidc_client, user=user, scopes=["view-resource"]
    )
    resp = client.get(
        reverse("idp_rest_framework_resource"), HTTP_AUTHORIZATION=f"bearer {token}"
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["user_email"] == user.email


def test_resource_without_user(db, client, access_token_factory, oidc_client):
    token, _ = access_token_factory(
        client=oidc_client, user=None, scopes=["view-resource"]
    )
    resp = client.get(
        reverse("idp_rest_framework_resource"), HTTP_AUTHORIZATION=f"bearer {token}"
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["user_email"] is None


def test_resource_forbidden(db, client, access_token_factory, user, oidc_client):
    token, _ = access_token_factory(
        client=oidc_client, user=user, scopes=["other-resource"]
    )
    resp = client.get(
        reverse("idp_rest_framework_resource"), HTTP_AUTHORIZATION=f"bearer {token}"
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.parametrize(
    "resources,success",
    [
        ([], True),
        (["https://some.other/resource"], False),
        (["http://testserver/idp/drf/resource"], True),
        (["http://testserver/idp/drf/resource/sub"], False),
        (["http://testserver/idp/drf"], True),
        (["http://testserver/idp/drf/other-resource"], False),
        (
            [
                "http://testserver/idp/drf/other-resource",
                "http://testserver/idp/drf/resource",
            ],
            True,
        ),
    ],
)
def test_resources_granted(
    db, client, access_token_factory, user, oidc_client, resources, success
):
    token, _ = access_token_factory(
        client=oidc_client,
        user=user,
        scopes=["view-resource"],
        resources=resources,
    )
    resp = client.get(
        reverse("idp_rest_framework_resource"), HTTP_AUTHORIZATION=f"bearer {token}"
    )
    if success:
        assert resp.status_code == HTTPStatus.OK
    else:
        assert resp.status_code == HTTPStatus.FORBIDDEN

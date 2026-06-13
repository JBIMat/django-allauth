from http import HTTPStatus

import pytest


def test_resource(db, client, access_token_factory, user, oidc_client):
    token, _ = access_token_factory(
        client=oidc_client, user=user, scopes=["view-resource"]
    )
    resp = client.get("/idp/ninja/resource", HTTP_AUTHORIZATION=f"bearer {token}")
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["user_email"] == user.email


def test_resource_using_id_token(db, client, id_token_factory, user, oidc_client):
    token = id_token_factory(client=oidc_client, user=user)
    resp = client.get("/idp/ninja/resource", HTTP_AUTHORIZATION=f"bearer {token}")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_resource_forbidden(db, client, access_token_factory, user, oidc_client):
    token, _ = access_token_factory(
        client=oidc_client, user=user, scopes=["other-resource"]
    )
    resp = client.get("/idp/ninja/resource", HTTP_AUTHORIZATION=f"bearer {token}")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_resource_user_inactive(db, client, access_token_factory, user, oidc_client):
    user.is_active = False
    user.save(update_fields=["is_active"])
    token, _ = access_token_factory(
        client=oidc_client, user=user, scopes=["view-resource"]
    )
    resp = client.get("/idp/ninja/resource", HTTP_AUTHORIZATION=f"bearer {token}")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize(
    "resources,success",
    [
        ([], True),
        (["https://some.other/resource"], False),
        (["http://testserver/idp/ninja/resource"], True),
        (["http://testserver/idp/ninja/resource/sub"], False),
        (["http://testserver/idp/ninja"], True),
        (["http://testserver/idp/ninja/other-resource"], False),
        (
            [
                "http://testserver/idp/ninja/other-resource",
                "http://testserver/idp/ninja/resource",
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
    resp = client.get("/idp/ninja/resource", HTTP_AUTHORIZATION=f"bearer {token}")
    if success:
        assert resp.status_code == HTTPStatus.OK
    else:
        assert resp.status_code == HTTPStatus.FORBIDDEN

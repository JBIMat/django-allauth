from urllib.parse import parse_qs, urlparse

from django.contrib.sites.models import Site
from django.test import override_settings
from django.urls import reverse

import pytest

from allauth.socialaccount.adapter import (
    DefaultSocialAccountAdapter,
    _build_apps_from_settings,
    get_adapter,
)
from allauth.socialaccount.internal import statekit
from allauth.socialaccount.models import SocialApp


class PrefixStateSocialAccountAdapter(DefaultSocialAccountAdapter):
    def generate_state_param(self, state: dict) -> str:
        return f"prefix-{super().generate_state_param(state)}"


def test_generate_state_param(settings, client, db, google_provider_settings):
    settings.SOCIALACCOUNT_ADAPTER = (
        "tests.apps.socialaccount.test_adapter.PrefixStateSocialAccountAdapter"
    )
    resp = client.post(reverse("google_login"))
    parsed = urlparse(resp["location"])
    query = parse_qs(parsed.query)
    state = query["state"][0]
    assert len(state) == len("prefix-") + statekit.STATE_ID_LENGTH
    assert state.startswith("prefix-")


def test_list_db_based_apps(db, settings):
    app = SocialApp.objects.create(
        provider="saml", provider_id="urn:idp-identity-id", client_id="org-slug"
    )
    app.sites.add(Site.objects.get_current())
    apps = get_adapter().list_apps(None, provider="saml", client_id="org-slug")
    assert app.pk in [a.pk for a in apps]


def test_list_settings_based_apps(db, settings):
    settings.SOCIALACCOUNT_PROVIDERS = {
        "saml": {
            "APPS": [
                {
                    "provider_id": "urn:idp-entity-id",
                    "client_id": "org-slug",
                }
            ]
        }
    }
    apps = get_adapter().list_apps(None, provider="saml", client_id="org-slug")
    assert len(apps) == 1
    app = apps[0]
    assert not app.pk
    assert app.client_id == "org-slug"


@override_settings(
    SOCIALACCOUNT_PROVIDERS={
        "saml": {
            "APPS": [
                {
                    "name": "IdP",
                    "provider_id": "urn:idp-entity-id",
                    "client_id": "org-slug",
                    "secret": "sekret",
                    "key": "the-key",
                    "settings": {"sso_url": "https://idp.example.com/sso"},
                }
            ]
        }
    }
)
def test_build_apps_from_settings_fields():
    provider_to_apps = _build_apps_from_settings()
    assert list(provider_to_apps.keys()) == ["saml"]
    apps = provider_to_apps["saml"]
    assert len(apps) == 1
    app = apps[0]
    assert isinstance(app, SocialApp)
    assert not app.pk
    assert app.provider == "saml"
    assert app.name == "IdP"
    assert app.provider_id == "urn:idp-entity-id"
    assert app.client_id == "org-slug"
    assert app.secret == "sekret"
    assert app.key == "the-key"
    assert app.settings == {"sso_url": "https://idp.example.com/sso"}


@override_settings(
    SOCIALACCOUNT_PROVIDERS={
        "saml": {
            "APP": {
                "provider_id": "urn:idp-entity-id",
                "client_id": "org-slug",
                "certificate_key": "-----BEGIN CERTIFICATE-----",
            }
        }
    }
)
def test_build_apps_from_settings_certificate_key_deprecation():
    with pytest.warns(UserWarning, match="certificate_key"):
        provider_to_apps = _build_apps_from_settings()
    app = provider_to_apps["saml"][0]
    assert app.settings["certificate_key"] == "-----BEGIN CERTIFICATE-----"


@override_settings(
    SOCIALACCOUNT_PROVIDERS={
        "saml": {
            "APPS": [
                {"provider_id": "urn:idp-a", "client_id": "org-a"},
                {"provider_id": "urn:idp-b", "client_id": "org-b"},
            ]
        }
    }
)
def test_build_apps_from_settings_filtering():
    def client_ids(provider_to_apps):
        return [app.client_id for apps in provider_to_apps.values() for app in apps]

    assert client_ids(_build_apps_from_settings(client_id="org-b")) == ["org-b"]
    # provider= matches either the app's provider_id or its provider.
    assert client_ids(_build_apps_from_settings(provider="urn:idp-a")) == ["org-a"]
    assert client_ids(_build_apps_from_settings(provider="saml")) == ["org-a", "org-b"]
    assert client_ids(_build_apps_from_settings(provider="nope")) == []


def test_get_signup_form_initial_data(sociallogin_factory):
    sociallogin = sociallogin_factory(email="a@b.com")
    # it should pick up sociallogin.email_addresses
    sociallogin.user.email = ""
    initial_data = get_adapter().get_signup_form_initial_data(sociallogin)
    assert initial_data["email"] == "a@b.com"

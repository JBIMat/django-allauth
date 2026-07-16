from http import HTTPStatus

from django import forms
from django.urls import reverse


def test_openapi_json(client):
    resp = client.get(reverse("headless:openapi_json"))
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data["openapi"] == "3.0.3"
    assert data["info"]["description"].startswith("# Introduction")


class SpecCustomSignupForm(forms.Form):
    favorite_color = forms.ChoiceField(choices=[("red", "Red"), ("blue", "Blue")])
    hobbies = forms.MultipleChoiceField(
        choices=[("chess", "Chess"), ("poker", "Poker")],
        required=True,
        help_text="Pick your hobbies.",
    )
    nickname = forms.CharField(min_length=2, max_length=30, help_text="Your nickname.")
    age = forms.IntegerField()
    rating = forms.FloatField()
    newsletter = forms.BooleanField()
    birth_date = forms.DateField()
    signed_up_at = forms.DateTimeField()
    contact_email = forms.EmailField()
    website = forms.URLField()
    balance = forms.DecimalField()

    def signup(self, request, user):
        pass


def test_openapi_json_with_custom_signup_form(settings, client):
    settings.ACCOUNT_SIGNUP_FORM_CLASS = (
        "tests.apps.headless.spec.test_views.SpecCustomSignupForm"
    )
    resp = client.get(reverse("headless:openapi_json"))
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    base_signup = data["components"]["schemas"]["BaseSignup"]
    assert base_signup["properties"]["favorite_color"] == {
        "type": "string",
        "enum": ["red", "blue"],
    }
    assert base_signup["properties"]["hobbies"] == {
        "type": "array",
        "items": {"type": "string", "enum": ["chess", "poker"]},
        "description": "Pick your hobbies.",
    }
    assert base_signup["properties"]["nickname"] == {
        "type": "string",
        "maxLength": 30,
        "minLength": 2,
        "description": "Your nickname.",
    }
    assert base_signup["properties"]["age"] == {"type": "integer"}
    assert base_signup["properties"]["rating"] == {"type": "number"}
    assert base_signup["properties"]["newsletter"] == {"type": "boolean"}
    assert base_signup["properties"]["birth_date"] == {
        "type": "string",
        "format": "date",
    }
    assert base_signup["properties"]["signed_up_at"] == {
        "type": "string",
        "format": "date-time",
    }
    assert base_signup["properties"]["contact_email"] == {
        "type": "string",
        "format": "email",
        "maxLength": 320,
    }
    assert base_signup["properties"]["website"] == {
        "type": "string",
        "format": "uri",
    }
    assert base_signup["properties"]["balance"] == {
        "type": "string",
        "format": "decimal",
        "pattern": r"^\d+(\.\d+)?$",
    }
    assert "hobbies" in base_signup["required"]

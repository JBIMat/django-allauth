from datetime import timedelta

from django.core.management import call_command
from django.utils import timezone

from allauth.idp.oidc.models import Token


def test_cleartokens_deletes_only_expired(
    oidc_client, user, access_token_generator, capsys
):
    now = timezone.now()
    _, expired = access_token_generator(
        oidc_client, user, expires_at=now - timedelta(seconds=1)
    )
    _, valid = access_token_generator(
        oidc_client, user, expires_at=now + timedelta(hours=1)
    )
    _, never = access_token_generator(oidc_client, user, expires_at=None)

    call_command("oidc_cleartokens")

    assert not Token.objects.filter(pk=expired.pk).exists()
    assert Token.objects.filter(pk=valid.pk).exists()
    assert Token.objects.filter(pk=never.pk).exists()
    assert "1 expired token(s) deleted." in capsys.readouterr().out

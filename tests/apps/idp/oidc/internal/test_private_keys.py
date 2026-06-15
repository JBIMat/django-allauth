from datetime import timedelta

from django.utils import timezone

from allauth.idp.oidc.internal.private_keys import filter_keys, pick_signing_key
from allauth.idp.oidc.models import PrivateKey


def _key(pem="pem", **kwargs):
    return PrivateKey(pem=pem, **kwargs)


def test_filter_keys_without_flags_returns_all():
    keys = [_key(pem="a"), _key(pem="b")]
    assert filter_keys(keys) == keys


def test_filter_keys_did_activate_excludes_future_not_before():
    now = timezone.now()
    active = _key(pem="active", not_before=now - timedelta(seconds=60))
    pending = _key(pem="pending", not_before=now + timedelta(seconds=60))
    undated = _key(pem="undated")
    keys = [active, pending, undated]
    assert filter_keys(keys, did_activate=True) == [active, undated]


def test_filter_keys_is_active_excludes_expired():
    now = timezone.now()
    fresh = _key(pem="fresh", expires_at=now + timedelta(seconds=60))
    expired = _key(pem="expired", expires_at=now - timedelta(seconds=60))
    undated = _key(pem="undated")
    keys = [fresh, expired, undated]
    assert filter_keys(keys, is_active=True) == [fresh, undated]


def test_filter_keys_combines_flags():
    now = timezone.now()
    usable = _key(
        pem="usable",
        not_before=now - timedelta(seconds=60),
        expires_at=now + timedelta(seconds=60),
    )
    pending = _key(pem="pending", not_before=now + timedelta(seconds=60))
    expired = _key(pem="expired", expires_at=now - timedelta(seconds=60))
    keys = [usable, pending, expired]
    assert filter_keys(keys, did_activate=True, is_active=True) == [usable]


def test_pick_signing_key_empty():
    assert pick_signing_key([]) is None


def test_pick_signing_key_single():
    key = _key()
    assert pick_signing_key([key]) is key


def test_pick_signing_key_prefers_most_recently_issued():
    now = timezone.now()
    older = _key(pem="older", issued_at=now - timedelta(days=2))
    newer = _key(pem="newer", issued_at=now - timedelta(days=1))
    assert pick_signing_key([older, newer]) is newer
    assert pick_signing_key([newer, older]) is newer


def test_pick_signing_key_falls_back_to_not_before():
    now = timezone.now()
    older = _key(pem="older", not_before=now - timedelta(days=2))
    newer = _key(pem="newer", not_before=now - timedelta(days=1))
    assert pick_signing_key([older, newer]) is newer
    assert pick_signing_key([newer, older]) is newer


def test_pick_signing_key_dated_beats_undated():
    now = timezone.now()
    undated = _key(pem="undated")
    dated = _key(pem="dated", issued_at=now - timedelta(days=365))
    assert pick_signing_key([undated, dated]) is dated
    assert pick_signing_key([dated, undated]) is dated

import pytest

from allauth.core.internal import ratelimit


def test_rollback_consume(rf, enable_cache):
    def consume():
        request = rf.post("/")
        config = {"foo": "2/m/ip"}
        return ratelimit.consume(request, config=config, action="foo")

    usage1 = consume()
    assert len(usage1.usage) > 0
    usage2 = consume()
    assert len(usage2.usage) > 0
    no_usage = consume()
    assert no_usage is None
    usage1.rollback()
    assert consume()
    assert not consume()


def test_apply_rate():
    rate = ratelimit.Rate(amount=2, duration=60, per="ip")
    now = 1000.0

    # First hit against an empty history: allowed and recorded.
    allowed, history = ratelimit.apply_rate([], now, rate)
    assert allowed
    assert history == [now]

    # Second hit within the window: allowed, recorded newest-first.
    allowed, history = ratelimit.apply_rate(history, now + 1, rate)
    assert allowed
    assert history == [now + 1, now]

    # Third hit within the window: over the limit, nothing recorded.
    allowed, history = ratelimit.apply_rate(history, now + 2, rate)
    assert not allowed
    assert history == [now + 1, now]

    # A dry run never records, even when allowed.
    allowed, history = ratelimit.apply_rate([], now, rate, dry_run=True)
    assert allowed
    assert history == []

    # Timestamps older than the duration are dropped, freeing capacity.
    allowed, history = ratelimit.apply_rate([now - 61, now - 62], now, rate)
    assert allowed
    assert history == [now]


@pytest.mark.parametrize(
    "rate,values",
    [
        ("5/m", [(5, 60, "ip")]),
        ("5/m/user", [(5, 60, "user")]),
        ("2/3.5m/key", [(2, 210, "key")]),
        ("3/5m/user,20/0.5m/ip", [(3, 300, "user"), (20, 30, "ip")]),
        ("7/2h", [(7, 7200, "ip")]),
        ("7/0.25d", [(7, 21600, "ip")]),
    ],
)
def test_parse(rate, values):
    rates = ratelimit.parse_rates(rate)
    assert len(rates) == len(values)
    for i, rate in enumerate(rates):
        assert rate.amount == values[i][0]
        assert rate.duration == values[i][1]
        assert rate.per == values[i][2]


@pytest.mark.parametrize(
    "ip,prefix,expected",
    [
        ("192.168.1.1", 64, "192.168.1.1"),
        ("10.0.0.255", 48, "10.0.0.255"),
        ("2001:db8:85a3::8a2e:370:7334", 64, "2001:db8:85a3::"),
        ("2001:db8:85a3:1234:5678:abcd:ef01:2345", 64, "2001:db8:85a3:1234::"),
        ("2001:db8:85a3:1234:5678:abcd:ef01:2345", 48, "2001:db8:85a3::"),
        (
            "2001:db8:85a3:1234:5678:abcd:ef01:2345",
            128,
            "2001:db8:85a3:1234:5678:abcd:ef01:2345",
        ),
        ("::1", 64, "::"),
        ("invalid", 64, "invalid"),
    ],
)
def test_truncate_ip(ip, prefix, expected, settings):
    settings.ALLAUTH_RATE_LIMIT_IPV6_PREFIX = prefix
    assert ratelimit.truncate_ip(ip) == expected

Configuration
=============

Available settings:

``IDP_OIDC_ACCESS_TOKEN_EXPIRES_IN`` (default: 3600)
  The time (in seconds) after which access tokens expire.

``IDP_OIDC_ACCESS_TOKEN_FORMAT`` (default: ``"opaque"``)
  The format of issued access tokens. This can be ``"opaque"`` for randomized
  strings, or, ``"jwt"`` for JWT based access tokens.

``IDP_OIDC_ADAPTER`` (default: ``"allauth.idp.oidc.adapter.DefaultOIDCAdapter"``)
  Specifies the adapter class to use, allowing you to alter certain
  default behavior.

``IDP_OIDC_AUTHORIZATION_CODE_EXPIRES_IN`` (default: 60)
  The time (in seconds) after which authorization codes expire.

``IDP_OIDC_DCR_ENABLED`` (default: ``False``)
  Controls whether Dynamic Client Registration is enabled. When enabled, clients
  can register themselves by POSTing to the registration endpoint.

``IDP_OIDC_DCR_REQUIRES_INITIAL_ACCESS_TOKEN`` (default: ``True``)
  When enabled, the DCR endpoint requires an initial access token in the
  ``Authorization`` header (``Bearer <token>``). This limits registration to
  previously authorized parties.

``IDP_OIDC_CIMD_CACHE_TIMEOUT`` (default: 3600)
  The time (in seconds) to cache fetched CIMD metadata before re-fetching.

``IDP_OIDC_CIMD_ENABLED`` (default: ``False``)
  Controls whether Client ID Metadata Document support is enabled. When enabled,
  clients can use an HTTPS URL as their ``client_id``.

``IDP_OIDC_DEVICE_CODE_EXPIRES_IN`` (default: 300)
  The time (in seconds) after which device codes expire.

``IDP_OIDC_DEVICE_CODE_INTERVAL`` (default: 5)
  The time (in seconds) a client should wait between polling attempts when using
  the device authorization flow.

``IDP_OIDC_ID_TOKEN_EXPIRES_IN`` (default: 300)
  The time (in seconds) after which ID tokens expire.

``IDP_OIDC_USER_CODE_FORMAT`` (default: ``settings.ALLAUTH_USER_CODE_FORMAT``)
  Controls the format of the user code.

``IDP_OIDC_PRIVATE_KEY`` (default: ``""``)
  A string containing the PEM-encoded private key used for signing ID tokens and
  JWT access tokens (and for serving ``.well-known/jwks.json``). This is the
  simplest way to configure a single signing key. For key rotation, use
  ``IDP_OIDC_PRIVATE_KEYS`` instead.

``IDP_OIDC_PRIVATE_KEYS`` (default: ``[]``)
  A list of private keys, used to support key rotation. Each entry is a
  dictionary describing a single key::

      IDP_OIDC_PRIVATE_KEYS = [
          {
              "pem": "-----BEGIN PRIVATE KEY-----\n...",
              "not_before": "2026-01-01T00:00:00+00:00",
              "expires_at": "2026-04-01T00:00:00+00:00",
              "issued_at": "2025-12-01T00:00:00+00:00",
          },
          ...
      ]

  The ``pem`` field (the PEM-encoded private key) is required. The
  ``not_before``, ``expires_at`` and ``issued_at`` fields are optional and may
  be passed either as ISO 8601 strings or as ``datetime`` objects (naive
  datetimes are interpreted as UTC).

  A key is published in ``.well-known/jwks.json`` and trusted for verifying
  tokens from the moment it is configured until its ``expires_at`` is reached
  (``not_before`` does not affect this -- keys are pre-published so clients can
  pick them up ahead of time). New tokens are always signed with the most
  recently *issued* key (``issued_at``, falling back to ``not_before``) that has
  activated and not yet expired.

  To rotate, add the new key with a later ``issued_at`` than the incumbent;
  signing switches to it automatically. Set an ``expires_at`` on the previous
  key far enough in the future that every token it signed has expired (and the
  JWKS cache window has elapsed) before it is removed. Until then the old key
  remains verify-only.

  Any key configured via ``IDP_OIDC_PRIVATE_KEY`` is automatically included in
  this list (without ``issued_at``), so it is treated as the oldest key and any
  dated key in ``IDP_OIDC_PRIVATE_KEYS`` takes over signing.

``IDP_OIDC_JWKS_CACHE_CONTROL`` (default: 3600)
  Controls the cache control max age (in seconds) of the ``.well-known/jwks.json``
  response. The value is automatically clamped so that it never exceeds the time
  until the next key drops out of the key set (the soonest ``expires_at``),
  ensuring clients refetch before a key they may still rely on is removed.


``IDP_OIDC_RATE_LIMITS`` (default: ``{"device_user_code": "5/m/ip", "client_registration": "3/m/ip", "cimd_fetch": "3/m/ip"}``)
  Rate limit configuration.

``IDP_OIDC_REFRESH_TOKEN_EXPIRES_IN`` (default: ``None``)
  Set to a positive number of seconds to make refresh tokens expire. By
  default (``None``) refresh tokens do not expire. With
  ``IDP_OIDC_ROTATE_REFRESH_TOKEN`` enabled, each rotation issues a fresh
  token carrying a new expiry, resulting in a sliding (inactivity) window.
  With rotation disabled, the refresh token -- and its original expiry -- is
  reused as is, so the value acts as an absolute lifetime. Refresh tokens
  issued before this setting was enabled are unaffected by it. Whenever a
  refresh token carries an expiry, its remaining lifetime is returned to the
  client as ``refresh_expires_in`` (seconds) in the token response. Expired
  tokens are rejected, but not automatically purged from the database.

``IDP_OIDC_ROTATE_REFRESH_TOKEN`` (default: ``True``)
  When access tokens are refreshed the old refresh token can be kept
  (``False``) or replaced (``True``) with a new one (rotated).

``IDP_OIDC_RP_INITIATED_LOGOUT_ASKS_FOR_OP_LOGOUT`` (default: ``True``)
  During the RP initiated logout, the OIDC specification recommends that the end
  user is asked whether or not to logout of the OP as well. When this setting is
  ``True``, the end user is always asked. When ``False``, the user is only asked
  if needed according to the specification.

``IDP_OIDC_USERINFO_ENDPOINT`` (default: ``None``)
  This setting can be used to point the ``userinfo_endpoint`` value as returned
  in the ".well-known/openid-configuration" to a custom URL.  Setting this
  disables the built-in userinfo endpoint.

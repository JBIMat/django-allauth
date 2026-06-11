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
  The private key used for creating ID tokens (and ``.well-known/jwks.json``).

``IDP_OIDC_PREVIOUS_PRIVATE_KEY`` (default: ``""``)
  The previous private key used for creating ID tokens (and ``.well-known/jwks.json``).
  It is recommended to keep the previous private key around for a while after rotating keys,
  to allow existing tokens to be verified.

``IDP_OIDC_DECOMMISSION_PREVIOUS_KEY_AT`` (default: ``""``)
  The datetime at which the previous private key should be decommissioned automatically.
  When creating this datetime, respect Django's ``USE_TZ`` setting: use a timezone-aware datetime
  when ``USE_TZ=True``.
  After the decommission datetime has passed, the previous private key will no longer be available
  for verifying tokens, and will not be included in the ``.well-known/jwks.json`` response.
  When set, this also controls the cache control max age of the ``.well-known/jwks.json`` response,
  to ensure that clients will fetch the new keys in time.
  It is recommended to set the decommission datetime to a reasonable time after rotating keys,
  to allow existing tokens to be verified until they expire.
  If not set, the previous private key will be kept indefinitely.

``IDP_OIDC_JWKS_CACHE_CONTROL`` (default: ``""``)
  Controls the cache control max age (in seconds) of the ``.well-known/jwks.json`` response.
  If a decommission datetime is set for the previous private key, this will be overridden to
  ensure that clients will fetch the new keys in time.


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

from __future__ import annotations

from typing import Any

import jwt

from allauth.core.internal import jwkkit
from allauth.idp.oidc.adapter import get_adapter


def decode_jwt_token(
    value: str, *, client_id: str | None = None, verify_exp: bool, verify_iss: bool
) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        headers = jwt.get_unverified_header(value)

        if "kid" not in headers:
            return None

        adapter = get_adapter()
        for key in adapter.get_private_keys():
            jwk_dict, private_key = jwkkit.load_jwk_from_pem(key)
            if jwk_dict["kid"] == headers["kid"]:
                break
        else:
            return None

        issuer: str | None = None
        audience: str | None = None
        if client_id:
            audience = client_id
        if verify_iss:
            issuer = adapter.get_issuer()
        return jwt.decode(
            value,
            key=private_key.public_key(),
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_iss": verify_iss,
                "verify_aud": client_id is not None,
                "verify_exp": verify_exp,
            },
            audience=audience,
            issuer=issuer,
        )
    except jwt.PyJWTError:
        return None

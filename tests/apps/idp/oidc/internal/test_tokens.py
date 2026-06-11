from unittest.mock import patch

import jwt

from allauth.core.internal import jwkkit
from allauth.idp.oidc.internal.tokens import decode_jwt_token
from tests.projects.common.settings import IDP_OIDC_PRIVATE_KEY


PREVIOUS_PRIVATE_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDg1zDW72ZeMYxh
1HVhFWGiWIisQgX5O9cRdxtsSuvE4EZx6G1MNTaVZk3WiZ5CEFFRw1hYNd55Zxr5
kZFvbyKnrlj+EohjLRsLhW5S6Cp1LU3RrlRU6TW5EP6IFndbxOhZSpqkD/M6yuyg
Cs4/JRFdQDWXZ93BRZ1vLqaATOK7pGjrtfKII2YT8LWF7/zG5P4lgihq1CEBgycA
lB1DL3/FEFCstniW6K4yMWK2QFNoyvMAjZr5w8wgolkQfo2OJG/QO9ZMLcy1Tfgl
jjEle7xuTcx2mcTGgRDAfSsXoSPqUf3HIrguiZkLBgQgspCvvmZGhVfbGYGMiLoY
C+TPcV2BAgMBAAECggEAbDEgn0yzxb+x/aFumjjfsm9H1RwwI65X31+hIosqyKHj
RAzEC1fP3DROYF34eXHAr8eAS3Igi+rBYDZb9XNVCbsrt5bTamXaDcE3RU3SoHAc
cjmg+vr9jwBOes3UwaQO6mir4SaLtE7RbnHErT35DRZIs4KXgtks2MNp+3MD56Ze
pYH5Omq7ZE4JVJfdyrpA1o4uHuGdalVfKYiMdwg8mObtbzkFjQvaWUKMaOc55T/p
/F7Ypquwh/xAvIh4jfDwnZZpbHNY24DI2o7Q9afVvg/XtiW/uzhKnK7ExxCgmmEH
RjKNl1ZADAu90vgLvzIILNly6zH1nSGlTBI21uWswQKBgQD0zDOu4FUh9cF5tmDw
8jfqtm3osWozc/xO/0sz4F1Ex2lndUSA5TDCARoSc2t03HmpdPSXTCFlEQRNeQRY
d/mdNT560o4iGV4pYm7i7hNrqWMx+zEU/GpFMB8hFHpimIC8a8WXYn12FxHmd8fX
daWxbsFe9ObaxaGjlftFu9YCbwKBgQDrITE6NAwsW2mzSDXtSYF4mz9VDIqPB9qr
2oRZeo07oYk/BP+AaX3vRHgH0rZ0M8mQwGN2MMgCoaHe+GzrAEUSIVyif36iC9Fh
LbG4bLfXaQsoRBlo/sGsnIAOgshlytr7rkeJZxjOHtlo32uUBYMFYSs7O1yY4wdH
fhuCCeTXDwKBgQC0ErZ+EJVvSsmMz+UVuQf7B0FoZ4G44bwbHF7khUn2uz3FFhVT
P8UTIR5drjvAliKEzfzSgvUZ1F+24auZrH+Y7j7MuLBHUyPaC4eINRtiGhNXA/GB
/3/o71Im0lqIxqgEcr7B8nhZ8vR+9WOzEd7V26QxRrO/AJw7qqtRC7CMzwKBgEcA
WOsoeFyUphB7R72FqtEOoEtAZD7YslGexMR4W1mcZ+Nd0QGn2V19IXnLSUlBsiZB
0kcIZ/1TbZv1DH7SMAlPhbeUJFsukmVz9Oyp98HWeIYKOloYQ8ep4ol/OKB0ZzgE
4pk9RqJHcoNWpBeoqm3fb7yNKmMIe1Q9YnUcI7xFAoGBAJw41i/S4oOnpaNK/hfm
inakRKiCwYUMIzyOEu7P4+Uv+s/Vbyc0ujLqaAtRMQ+OdVutw8YRwI4I2/M/N5TC
7v5xldYOIWjsN5Kp2G2cvoFUT6UFQZj0qvmR9LL/C+bdBpMq0W5+NLwn0pGJs+gz
BfXb9qX2K0qCJY0CCjmTOgc9
-----END PRIVATE KEY-----
"""


def _generate_token(private_key_pem: str, *, with_kid: bool) -> str:
    payload = {"sub": "abc"}
    jwk_dict, private_key = jwkkit.load_jwk_from_pem(private_key_pem)
    headers = {"kid": jwk_dict["kid"]} if with_kid else None
    return jwt.encode(payload, key=private_key, algorithm="RS256", headers=headers)


def test_decode_jwt_token_without_kid_header():
    token = _generate_token(IDP_OIDC_PRIVATE_KEY, with_kid=False)
    with patch("allauth.idp.oidc.internal.tokens.get_adapter") as mock_get_adapter:
        assert (
            decode_jwt_token(token, verify_exp=False, verify_iss=False, client_id=None)
            is None
        )
    mock_get_adapter.assert_not_called()


def test_decode_jwt_token_with_PREVIOUS_PRIVATE_KEY_still_valid():
    token = _generate_token(PREVIOUS_PRIVATE_KEY, with_kid=True)
    with patch("allauth.idp.oidc.internal.tokens.get_adapter") as mock_get_adapter:
        mock_get_adapter.return_value.get_private_keys.return_value = [
            IDP_OIDC_PRIVATE_KEY,
            PREVIOUS_PRIVATE_KEY,
        ]
        payload = decode_jwt_token(
            token, verify_exp=False, verify_iss=False, client_id=None
        )
    assert payload is not None
    assert payload["sub"] == "abc"


def test_decode_jwt_token_with_PREVIOUS_PRIVATE_KEY_expired():
    token = _generate_token(PREVIOUS_PRIVATE_KEY, with_kid=True)
    with patch("allauth.idp.oidc.internal.tokens.get_adapter") as mock_get_adapter:
        mock_get_adapter.return_value.get_private_keys.return_value = [
            IDP_OIDC_PRIVATE_KEY,
        ]
        payload = decode_jwt_token(
            token, verify_exp=False, verify_iss=False, client_id=None
        )
    assert payload is None


def test_decode_jwt_token_with_current_private_key():
    token = _generate_token(IDP_OIDC_PRIVATE_KEY, with_kid=True)
    with patch("allauth.idp.oidc.internal.tokens.get_adapter") as mock_get_adapter:
        mock_get_adapter.return_value.get_private_keys.return_value = [
            IDP_OIDC_PRIVATE_KEY,
            PREVIOUS_PRIVATE_KEY,
        ]
        payload = decode_jwt_token(
            token, verify_exp=False, verify_iss=False, client_id=None
        )
    assert payload is not None
    assert payload["sub"] == "abc"

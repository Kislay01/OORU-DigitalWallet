"""Minimal test holder: a P-256 key that can claim a Campus ID over OpenID4VCI."""

import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import settings
from app.sdjwt import b64url


class TestHolder:
    __test__ = False

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = self.key.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64url(n.x.to_bytes(32, "big")), "y": b64url(n.y.to_bytes(32, "big"))}

    def proof(self, nonce: str, aud: str | None = None, iat: int | None = None) -> str:
        return jwt.encode(
            {"aud": aud or settings.public_base_url, "iat": iat or int(time.time()), "nonce": nonce},
            self.key,
            algorithm="ES256",
            headers={"typ": "openid4vci-proof+jwt", "jwk": self.jwk},
        )

    async def claim(self, client, offer: dict) -> str:
        code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        t = await client.post(
            "/api/v1/issuer/token",
            data={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": code},
        )
        assert t.status_code == 200, t.text
        tok = t.json()
        r = await client.post(
            "/api/v1/issuer/credential",
            headers={"Authorization": f"Bearer {tok['access_token']}"},
            json={"credential_configuration_id": "CampusID_SD_JWT", "proof": {"proof_type": "jwt", "jwt": self.proof(tok["c_nonce"])}},
        )
        assert r.status_code == 200, r.text
        return r.json()["credentials"][0]["credential"]

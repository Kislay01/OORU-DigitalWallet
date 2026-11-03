"""Issuer signing key (EC P-256) kept on disk so credentials stay verifiable across restarts."""

import base64
import datetime
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.config import settings
from app.sdjwt import b64url


class IssuerKey:
    def __init__(self, key_dir: Path) -> None:
        key_dir.mkdir(parents=True, exist_ok=True)
        key_path, cert_path = key_dir / "issuer-key.pem", key_dir / "issuer-cert.pem"

        if key_path.exists() and cert_path.exists():
            self.private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            self.certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        else:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            self.certificate = self._self_signed(self.private_key)
            key_path.write_bytes(
                self.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            key_path.chmod(0o600)
            cert_path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))

        self.public_key = self.private_key.public_key()
        nums = self.public_key.public_numbers()
        self.public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(nums.x.to_bytes(32, "big")),
            "y": b64url(nums.y.to_bytes(32, "big")),
        }
        thumb_input = json.dumps(
            {k: self.public_jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":")
        ).encode()
        self.kid = b64url(hashlib.sha256(thumb_input).digest())
        self.public_jwk.update({"kid": self.kid, "use": "sig", "alg": "ES256"})
        self.cert_b64 = base64.b64encode(self.certificate.public_bytes(serialization.Encoding.DER)).decode()
        self.cert_sha256 = self.certificate.fingerprint(hashes.SHA256()).hex()

    @staticmethod
    def _self_signed(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OORU Campus ID Issuer"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Campus ID Issuer"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )

    def jwks(self) -> dict:
        return {"keys": [self.public_jwk]}


@lru_cache
def issuer_key() -> IssuerKey:
    return IssuerKey(Path(settings.key_dir))

import json
import time
from datetime import date, timedelta

import jwt

from app.sdjwt import decode_disclosure, disclosure_digest, split
from tests.conftest import auth_header
from tests.holder import TestHolder

PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


def student(**over):
    base = {
        "name": "Asha Patil",
        "roll_number": "12412001",
        "branch": "CSE (AI)",
        "enrollment_status": "active",
        "valid_until": (date.today() + timedelta(days=365)).isoformat(),
    }
    base.update(over)
    return base


async def make_offer(client, **over):
    admin = await auth_header(client, "admin", "admin123")
    r = await client.post("/api/v1/issuer/offers", json=student(**over), headers=admin)
    assert r.status_code == 201, r.text
    return r.json(), admin


async def test_metadata(client):
    m = (await client.get("/.well-known/openid-credential-issuer")).json()
    assert "CampusID_SD_JWT" in m["credential_configurations_supported"]
    jwks = (await client.get("/.well-known/jwt-vc-issuer")).json()["jwks"]
    assert jwks["keys"][0]["crv"] == "P-256" and "d" not in jwks["keys"][0]


async def test_full_issuance_signature_and_disclosures(client):
    offer, _ = await make_offer(client)
    assert offer["credential_offer_uri"].startswith("openid-credential-offer://?credential_offer=")
    holder = TestHolder()
    sd_jwt = await holder.claim(client, offer["credential_offer"])

    issuer_jwt, disclosures, kb = split(sd_jwt)
    assert kb is None and len(disclosures) == 5

    jwk = (await client.get("/.well-known/jwt-vc-issuer")).json()["jwks"]["keys"][0]
    payload = jwt.decode(issuer_jwt, jwt.PyJWK.from_dict(jwk).key, algorithms=["ES256"])
    assert payload["vct"] == "CampusID"
    assert payload["credential_id"] == offer["credential_id"]
    assert payload["cnf"]["jwk"]["x"] == holder.jwk["x"]
    assert "name" not in payload  # hidden behind digests
    assert payload["status"]["url"].endswith(f"/api/v1/status/{offer['credential_id']}")

    revealed = {decode_disclosure(d)[1]: decode_disclosure(d)[2] for d in disclosures}
    assert revealed["name"] == "Asha Patil" and revealed["branch"] == "CSE (AI)"
    assert sorted(disclosure_digest(d) for d in disclosures) == sorted(payload["_sd"])


async def test_offer_cannot_be_reused(client):
    offer, _ = await make_offer(client)
    await TestHolder().claim(client, offer["credential_offer"])
    code = offer["pre_authorized_code"]
    r = await client.post("/api/v1/issuer/token", data={"grant_type": PRE_AUTH, "pre-authorized_code": code})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_grant"


async def test_student_data_dropped_after_delivery(client):
    from app.db import SessionLocal
    from app.models import CredentialOffer

    offer, _ = await make_offer(client)
    await TestHolder().claim(client, offer["credential_offer"])
    async with SessionLocal() as s:
        row = await s.get(CredentialOffer, offer["pre_authorized_code"])
        assert row.redeemed and row.claims_json is None


async def test_wrong_nonce_and_stale_proof_rejected(client):
    offer, _ = await make_offer(client)
    holder = TestHolder()
    t = (await client.post("/api/v1/issuer/token", data={"grant_type": PRE_AUTH, "pre-authorized_code": offer["pre_authorized_code"]})).json()
    hdr = {"Authorization": f"Bearer {t['access_token']}"}

    bad = await client.post("/api/v1/issuer/credential", headers=hdr, json={"credential_configuration_id": "CampusID_SD_JWT", "proof": {"proof_type": "jwt", "jwt": holder.proof("wrong")}})
    assert bad.json()["detail"]["error"] == "invalid_nonce"

    stale = await client.post("/api/v1/issuer/credential", headers=hdr, json={"credential_configuration_id": "CampusID_SD_JWT", "proof": {"proof_type": "jwt", "jwt": holder.proof(t["c_nonce"], iat=int(time.time()) - 3600)}})
    assert stale.json()["detail"]["error"] == "invalid_proof"

    wrong_aud = await client.post("/api/v1/issuer/credential", headers=hdr, json={"credential_configuration_id": "CampusID_SD_JWT", "proof": {"proof_type": "jwt", "jwt": holder.proof(t["c_nonce"], aud="https://evil.example")}})
    assert wrong_aud.json()["detail"]["error"] == "invalid_proof"


async def test_verifier_cannot_issue(client):
    verifier = await auth_header(client, "verifier", "verifier123")
    r = await client.post("/api/v1/issuer/offers", json=student(), headers=verifier)
    assert r.status_code == 403


async def test_validation(client):
    admin = await auth_header(client, "admin", "admin123")
    past = await client.post("/api/v1/issuer/offers", json=student(valid_until="2020-01-01"), headers=admin)
    assert past.status_code == 422
    bad_status = await client.post("/api/v1/issuer/offers", json=student(enrollment_status="alumni"), headers=admin)
    assert bad_status.status_code == 422


async def test_duplicate_roll_number_needs_replace(client):
    first, admin = await make_offer(client)
    dup = await client.post("/api/v1/issuer/offers", json=student(), headers=admin)
    assert dup.status_code == 409
    rep = await client.post("/api/v1/issuer/offers", json={**student(), "replace_existing": True}, headers=admin)
    assert rep.status_code == 201
    old = (await client.get(f"/api/v1/status/{first['credential_id']}")).json()
    assert old["status"] == "revoked"


async def test_bulk_issue_per_row_results(client):
    admin = await auth_header(client, "admin", "admin123")
    rows = [
        student(roll_number="B1"),
        student(roll_number="B2", valid_until="2001-01-01"),
        student(roll_number="B1"),
        {"name": "No Roll", "branch": "ME", "valid_until": student()["valid_until"]},
        student(roll_number="B3", enrollment_status="graduated"),
    ]
    r = await client.post("/api/v1/issuer/offers/bulk", json={"rows": rows}, headers=admin)
    assert r.status_code == 200, r.text
    res = r.json()
    assert [x["ok"] for x in res] == [True, False, False, False, True]
    assert "valid_until" in res[1]["error"]
    assert "Duplicate" in res[2]["error"]
    summary = (await client.get("/api/v1/credentials/summary", headers=admin)).json()
    assert summary["total"] == 2

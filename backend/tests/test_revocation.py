from tests.conftest import auth_header
from tests.holder import TestHolder
from tests.test_issuer import make_offer


async def test_revoke_flow(client):
    offer, admin = await make_offer(client)
    cid = offer["credential_id"]
    assert (await client.get(f"/api/v1/status/{cid}")).json()["status"] == "active"

    r = await client.post(f"/api/v1/credentials/{cid}/revoke", json={"reason": "Lost card"}, headers=admin)
    assert r.status_code == 200 and r.json()["revocation_reason"] == "Lost card"

    assert (await client.get(f"/api/v1/status/{cid}")).json()["status"] == "revoked"
    assert cid in (await client.get("/api/v1/revocations")).json()

    again = await client.post(f"/api/v1/credentials/{cid}/revoke", headers=admin)
    assert again.status_code == 409


async def test_revoked_offer_cannot_be_claimed(client):
    offer, admin = await make_offer(client)
    await client.post(f"/api/v1/credentials/{offer['credential_id']}/revoke", headers=admin)
    code = offer["pre_authorized_code"]
    t = (await client.post("/api/v1/issuer/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": code})).json()
    holder = TestHolder()
    r = await client.post(
        "/api/v1/issuer/credential",
        headers={"Authorization": f"Bearer {t['access_token']}"},
        json={"credential_configuration_id": "CampusID_SD_JWT", "proof": {"proof_type": "jwt", "jwt": holder.proof(t["c_nonce"])}},
    )
    assert r.json()["detail"]["error"] == "credential_request_denied"


async def test_unknown_status(client):
    assert (await client.get("/api/v1/status/CID-NOPE")).json()["status"] == "unknown"


async def test_registry_search_summary_audit(client):
    a, admin = await make_offer(client, roll_number="111")
    await make_offer(client, roll_number="222")
    await client.post(f"/api/v1/credentials/{a['credential_id']}/revoke", headers=admin)

    assert len((await client.get("/api/v1/credentials", params={"q": "222"}, headers=admin)).json()) == 1
    revoked = (await client.get("/api/v1/credentials", params={"status": "revoked"}, headers=admin)).json()
    assert [r["credential_id"] for r in revoked] == [a["credential_id"]]
    assert (await client.get("/api/v1/credentials/summary", headers=admin)).json() == {"total": 2, "active": 1, "revoked": 1, "expired": 0}

    actions = [e["action"] for e in (await client.get("/api/v1/audit", headers=admin)).json()]
    assert "revoke" in actions and "issue_offer" in actions


async def test_registry_admin_only(client):
    verifier = await auth_header(client, "verifier", "verifier123")
    assert (await client.get("/api/v1/credentials", headers=verifier)).status_code == 403

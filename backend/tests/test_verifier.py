import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from app.sdjwt import b64url, make_disclosure, split
from tests.conftest import auth_header
from tests.holder import TestHolder
from tests.test_issuer import make_offer

GATE = ["name", "enrollment_status", "valid_until"]


async def issued(client, **over):
    offer, admin = await make_offer(client, **over)
    holder = TestHolder()
    return holder, await holder.claim(client, offer["credential_offer"]), offer, admin


async def new_request(client, claims=GATE):
    v = await auth_header(client, "verifier", "verifier123")
    r = await client.post("/api/v1/verifier/requests", json={"requested_claims": claims}, headers=v)
    assert r.status_code == 201, r.text
    return r.json(), v


async def respond(client, req, vp):
    return await client.post("/api/v1/verifier/response", data={"state": req["request_id"], "vp_token": vp})


async def result(client, req, v):
    return (await client.get(f"/api/v1/verifier/requests/{req['request_id']}", headers=v)).json()


async def test_valid_presentation_reveals_only_chosen_fields(client):
    holder, sd, _, _ = await issued(client)
    req, v = await new_request(client)
    assert req["authorization_request_uri"].startswith("openid4vp://authorize?")
    assert "client_name" in req["authorization_request_uri"]
    vp = holder.present(sd, GATE, req["nonce"], req["client_id"])
    r = await respond(client, req, vp)
    assert r.json()["status"] == "valid"

    out = await result(client, req, v)
    assert out["status"] == "verified"
    assert set(out["result"]["claims"]) == set(GATE)
    assert "roll_number" not in out["result"]["claims"] and "branch" not in out["result"]["claims"]
    assert all(c["ok"] for c in out["result"]["checks"])


async def test_dcql_json_vp_token(client):
    holder, sd, _, _ = await issued(client)
    req, _ = await new_request(client, ["name"])
    vp = holder.present(sd, ["name"], req["nonce"], req["client_id"])
    r = await client.post("/api/v1/verifier/response", json={"state": req["request_id"], "vp_token": {"campus_id": [vp]}})
    assert r.json()["status"] == "valid"


async def test_request_is_single_use(client):
    holder, sd, _, _ = await issued(client)
    req, _ = await new_request(client)
    vp = holder.present(sd, GATE, req["nonce"], req["client_id"])
    assert (await respond(client, req, vp)).json()["status"] == "valid"
    again = await respond(client, req, vp)
    assert again.status_code == 409


async def test_replay_to_another_request_fails(client):
    holder, sd, _, _ = await issued(client)
    first, _ = await new_request(client)
    vp = holder.present(sd, GATE, first["nonce"], first["client_id"])
    second, v = await new_request(client)
    assert (await respond(client, second, vp)).json()["status"] == "invalid"
    reasons = (await result(client, second, v))["result"]["reasons"]
    assert any("nonce" in x for x in reasons)


async def test_missing_requested_field(client):
    holder, sd, _, _ = await issued(client)
    req, v = await new_request(client)
    vp = holder.present(sd, ["name"], req["nonce"], req["client_id"])
    assert (await respond(client, req, vp)).json()["status"] == "invalid"
    assert any("missing" in x for x in (await result(client, req, v))["result"]["reasons"])


async def test_forged_disclosure_rejected(client):
    holder, sd, _, _ = await issued(client)
    req, v = await new_request(client, ["name"])
    issuer_jwt, _, _ = split(sd)
    forged = issuer_jwt + "~" + make_disclosure("name", "Someone Else") + "~"
    from app.sdjwt import sd_hash

    kb = jwt.encode({"aud": req["client_id"], "nonce": req["nonce"], "iat": int(time.time()), "sd_hash": sd_hash(forged)}, holder.key, algorithm="ES256", headers={"typ": "kb+jwt"})
    assert (await respond(client, req, forged + kb)).json()["status"] == "invalid"
    assert any("not signed by the issuer" in x for x in (await result(client, req, v))["result"]["reasons"])


async def test_stolen_credential_without_holder_key_rejected(client):
    _, sd, _, _ = await issued(client)
    thief = ec.generate_private_key(ec.SECP256R1())
    req, v = await new_request(client)
    vp = TestHolder().present(sd, GATE, req["nonce"], req["client_id"], key=thief)
    assert (await respond(client, req, vp)).json()["status"] == "invalid"
    assert any(x.startswith("holder_binding") for x in (await result(client, req, v))["result"]["reasons"])


async def test_wrong_audience_and_stale_kb(client):
    holder, sd, _, _ = await issued(client)
    req, _ = await new_request(client)
    vp = holder.present(sd, GATE, req["nonce"], "https://other-verifier.example")
    assert (await respond(client, req, vp)).json()["status"] == "invalid"

    req2, _ = await new_request(client)
    stale = holder.present(sd, GATE, req2["nonce"], req2["client_id"], iat=int(time.time()) - 3600)
    assert (await respond(client, req2, stale)).json()["status"] == "invalid"


async def test_sd_hash_detects_dropped_disclosure_after_signing(client):
    holder, sd, _, _ = await issued(client)
    req, _ = await new_request(client, ["name"])
    vp = holder.present(sd, ["name", "branch"], req["nonce"], req["client_id"])
    parts = vp.split("~")
    tampered = "~".join([parts[0], parts[1], parts[-1]])  # remove one disclosure but keep the KB-JWT
    assert (await respond(client, req, tampered)).json()["status"] == "invalid"


async def test_untrusted_issuer_signature(client):
    holder, sd, _, _ = await issued(client)
    issuer_jwt, disclosures, _ = split(sd)
    payload = jwt.decode(issuer_jwt, options={"verify_signature": False})
    hdr = jwt.get_unverified_header(issuer_jwt)
    fake = jwt.encode(payload, ec.generate_private_key(ec.SECP256R1()), algorithm="ES256", headers={"typ": hdr["typ"], "kid": hdr["kid"]})
    forged_sd = fake + "~" + "".join(f"{d}~" for d in disclosures)
    req, v = await new_request(client, ["name"])
    vp = holder.present(forged_sd, ["name"], req["nonce"], req["client_id"])
    assert (await respond(client, req, vp)).json()["status"] == "invalid"
    assert any(x.startswith("issuer_signature") for x in (await result(client, req, v))["result"]["reasons"])


async def test_revoked_credential(client):
    holder, sd, offer, admin = await issued(client)
    await client.post(f"/api/v1/credentials/{offer['credential_id']}/revoke", headers=admin)
    req, v = await new_request(client)
    vp = holder.present(sd, GATE, req["nonce"], req["client_id"])
    assert (await respond(client, req, vp)).json()["status"] == "revoked"
    out = await result(client, req, v)
    assert out["status"] == "failed" and out["result"]["claims"] == {}


async def test_expired_request(client):
    from datetime import timedelta

    from app.db import SessionLocal
    from app.models import PresentationRequest
    from app.timeutil import utcnow

    holder, sd, _, _ = await issued(client)
    req, v = await new_request(client)
    async with SessionLocal() as s:
        row = await s.get(PresentationRequest, req["request_id"])
        row.expires_at = utcnow() - timedelta(seconds=1)
        await s.commit()
    vp = holder.present(sd, GATE, req["nonce"], req["client_id"])
    assert (await respond(client, req, vp)).status_code == 409
    assert (await result(client, req, v))["status"] == "expired"


async def test_manual_verify_history_and_summary(client):
    holder, sd, offer, _ = await issued(client)
    req, v = await new_request(client)
    vp = holder.present(sd, GATE, req["nonce"], req["client_id"])
    r = await client.post("/api/v1/verifier/verify", json={"request_id": req["request_id"], "presentation": vp}, headers=v)
    assert r.json()["status"] == "valid"

    await new_request(client)  # one still pending
    hist = (await client.get("/api/v1/verifier/history", headers=v)).json()
    assert len(hist) == 2
    done = next(h for h in hist if h["request_id"] == req["request_id"])
    assert "claims" not in done["result"] and set(done["result"]["fields_shared"]) == set(GATE)
    assert len((await client.get("/api/v1/verifier/history", params={"q": offer["credential_id"]}, headers=v)).json()) == 1
    assert (await client.get("/api/v1/verifier/summary", headers=v)).json() == {"total": 2, "verified": 1, "failed": 0, "pending": 1, "expired": 0}


async def test_request_validation_and_roles(client):
    _, v = await new_request(client)
    bad = await client.post("/api/v1/verifier/requests", json={"requested_claims": ["password"]}, headers=v)
    assert bad.status_code == 422
    assert (await client.post("/api/v1/verifier/requests", json={"requested_claims": ["name"]})).status_code == 401


async def test_request_object_endpoint(client):
    req, _ = await new_request(client)
    obj = (await client.get(f"/api/v1/verifier/requests/{req['request_id']}/object")).json()
    assert obj["nonce"] == req["nonce"] and obj["response_mode"] == "direct_post"
    assert [c["path"] for c in obj["dcql_query"]["credentials"][0]["claims"]] == [[c] for c in GATE]

from tests.conftest import auth_header


async def test_health(client):
    r = await client.get("/health")
    assert r.json() == {"status": "ok"}


async def test_login_and_me(client):
    headers = await auth_header(client, "admin", "admin123")
    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.json() == {"username": "admin", "role": "admin"}


async def test_wrong_password_rejected(client):
    r = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    assert r.json()["detail"]["error"]["code"] == "INVALID_CREDENTIALS"


async def test_missing_token_rejected(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401


async def test_tampered_token_rejected(client):
    headers = await auth_header(client, "verifier", "verifier123")
    headers["Authorization"] = headers["Authorization"][:-2] + "xx"
    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 401

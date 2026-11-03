# OORU Digital Identity Wallet — Campus ID

A privacy-first digital identity wallet for campus IDs, built for OORU on the
MOSIP Inji model. The college issues a signed Campus ID, the student holds it in
a wallet and chooses exactly which fields to reveal, a verifier checks it, and
the college can revoke it at any time.

**Flow:** issue → store → share → verify → revoke

**Standards:** W3C Verifiable Credentials · OpenID4VCI (pre-authorized code) ·
OpenID4VP · IETF SD-JWT VC with key binding

## Architecture

```
 ┌──────────────────┐   OpenID4VCI offer (QR)   ┌──────────────────┐
 │  Issuer portal   │ ────────────────────────▶ │  Holder wallet   │
 │  /admin          │   SD-JWT VC (ES256)       │  React + WebCrypto│
 └────────┬─────────┘ ◀──── proof of possession  └────────┬─────────┘
          │                                              │
          │ revoke                         OpenID4VP     │ SD-JWT + KB-JWT
          ▼                                (nonce, QR)   ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  FastAPI backend   issuer · verifier · revocation · audit        │
 │  PostgreSQL        accounts, credential metadata, requests, logs │
 └──────────────────────────────────────────────────────────────────┘
          ▲
          │ verify signature, disclosures, key binding, revocation
 ┌────────┴─────────┐
 │  Verifier portal │
 │  /verifier       │
 └──────────────────┘
```

The backend never stores credential contents. It keeps credential IDs,
revocation state, single-use request nonces and an audit trail.

## Repository layout

```
backend/            FastAPI app (shared core + one router module per feature)
  app/routers/      auto-registered: auth, health, issuer, verifier, ...
  app/models.py     shared data model
  app/campus_id.py  credential definition used by every component
portals/            static issuer and verifier web portals, auto-mounted
shared/             Campus ID schema (the contract between all three parts)
wallet/             holder wallet (React + TypeScript)
```

## Branches

| Branch | Scope |
|---|---|
| `main` | Shared foundation and integrated releases |
| `issuer` | Credential issuance (OpenID4VCI), issuer keys, revocation, admin portal |
| `verifier` | Presentation requests (OpenID4VP), SD-JWT verification, verifier portal |
| `wallet` | Holder wallet: key vault, claiming, selective disclosure, share history |

Each branch adds its own router module and portal folder, so they merge into
`main` without touching shared files. Merge order: `issuer` → `verifier` → `wallet`.

## Running locally

```bash
cd backend
cp ../.env.example .env
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

With Docker (PostgreSQL included):

```bash
docker compose up --build
```

Tests:

```bash
cd backend && python -m pytest -q
```

## Team

| Member | Area |
|---|---|
| Kislay Upadhyay | Issuer, revocation, shared backend |
| Himani | Verifier |
| Mahendrakumar | Holder wallet |
| Lucky | Wallet security and receipts |

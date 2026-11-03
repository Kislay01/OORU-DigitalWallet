# Campus ID Wallet

Holder wallet for the OORU Campus ID. Runs in the browser (React + TypeScript),
keeps everything on the device, and talks to issuers and verifiers over
OpenID4VCI and OpenID4VP.

## What it does

| Flow | How |
|---|---|
| **Add an ID** | Scan the college's QR (or paste the link). The wallet signs a proof with its own key, receives the SD-JWT, checks the issuer's signature against `/.well-known/jwt-vc-issuer` and confirms the credential is bound to its key before storing it. |
| **Share** | Scan a verifier's QR. The consent screen lists only the fields asked for, with a toggle each; nothing else is ever sent. The wallet builds a presentation with a key binding JWT (verifier audience, request nonce, `sd_hash`) and posts it to the verifier's `response_uri`, but only if it belongs to the same site as the verifier. |
| **Status** | Each ID shows Active / Revoked / Expired, checked against the issuer's status URL. Revoked or expired IDs can't be shared. |
| **Activity** | Every receive and share writes a receipt (who, which fields, SHA-256 of exactly what was sent). Receipts are hash-chained and signed with the wallet key, so edits, deletions or reordering are detected. Exportable as JSON. |

## Security model

- **Wallet key**: ECDSA P-256 generated with WebCrypto as **non-extractable**. It can sign but its private bytes can't be read, even by the app.
- **Two encryption layers at rest** (AES-256-GCM): every record is encrypted with a key derived from the 6-digit PIN (PBKDF2-SHA256, 310k rounds), then again with a non-extractable device key. Data copied off the device is useless without the device key; an unlocked phone is useless without the PIN.
- **PIN lockout**: 5 wrong attempts lock the wallet for 30 seconds.
- **Auto-lock** after 5 minutes idle. The PIN key is held only in memory while unlocked.

## Running

```bash
npm install
npm run dev          # http://localhost:3002
npm test             # unit tests
BACKEND_URL=http://localhost:8000 npm test   # plus a live issue → share → revoke round trip
```

The camera scanner needs HTTPS or `localhost`. On another device over plain
HTTP, paste the offer or request link instead, or open the wallet with
`?link=<url-encoded link>`.

## Credits

The wallet design builds on the team's earlier work: the React holder wallet
by **Mahendrakumar** (WebCrypto key vault, SD-JWT presentation, consent screen)
and the layered security and receipts model by **Lucky**.

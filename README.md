# Apex-PQ

**A post-quantum, passwordless identity portal for a university: ML-DSA-44 challenge-response login, an admin-approved identity registry anchored on a replicated hash-chain ledger, and a Chrome wallet extension with a passphrase-encrypted key vault.**

![status](https://img.shields.io/badge/status-research_prototype-orange)
![crypto](https://img.shields.io/badge/signatures-ML--DSA--44_(FIPS_204)-4c1)
![python](https://img.shields.io/badge/python-3.10+-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **Status: research / teaching prototype.** It demonstrates a sound authentication design, but it is not audited and has the limitations listed below. Do not use it to protect real accounts.

---

## What it does

| Component | What is real |
|---|---|
| **Login** | Server issues a random 256-bit single-use challenge (120 s TTL). The wallet signs `domain ‖ rp-id ‖ DID ‖ challenge` with **ML-DSA-44** (liboqs). The server verifies against the registered public key. No passwords. |
| **Registry** | Students submit a signup (DID + public key). The server checks that the DID is the hash of the key. An admin approves or rejects; approval is anchored on the ledger *before* the account is activated. |
| **Ledger** | Three SQLite replicas of a SHA3-256 hash chain with a genesis block, 2-of-3 write quorum, tip comparison and full re-verification of every block. Detects tampering. |
| **Wallet** | MV3 extension. Keys are stored in an AES-256-GCM vault under a PBKDF2-SHA256 (600k) key derived from your passphrase, with attempt throttling. |
| **Admin** | Approve / reject / edit / revoke identities, audit log, ledger explorer. Role is read from the database on every request. |

## Quickstart

```bash
git clone https://github.com/0x4rc4n3/Apex-PQ && cd Apex-PQ

# Docker (builds liboqs from the vendored source, runs as non-root, localhost-only port)
./run.sh docker            # http://127.0.0.1:8080

# or native (needs a liboqs shared library; point OQS_LIB at it)
pip install -r requirements.txt
OQS_LIB=/path/to/liboqs.so ./run.sh native
```

**First run:** the app generates an admin identity and writes `ADMIN_KEY_IMPORT_THEN_DELETE.json` (mode 0600) in the data directory (`pqc-identity/db/`, or `/data` in Docker; `docker compose cp apex-portal:/data/ADMIN_KEY_IMPORT_THEN_DELETE.json .`). Import it in the wallet, then **delete the file**. The server keeps only the public key.

### Install the wallet
1. `chrome://extensions` → enable Developer mode → **Load unpacked** → select `pqc-identity/wallet-extension/`.
2. Open the popup and create a passphrase (min. 10 characters; it cannot be recovered).
3. **Import identity** → paste the admin JSON, or sign up as a student (the new identity is handed to the wallet and encrypted when you next unlock it).

### Demo mode vs. hardened mode
This project has no in-browser ML-DSA implementation yet, so the demo generates keys and signs **on the server**:

| | `APEX_DEMO_MODE=1` (default for `run.sh` / compose, localhost only) | `APEX_DEMO_MODE=0` |
|---|---|---|
| `/api/keygen`, `/api/sign` | enabled (secret key transits the server) | disabled (404) |
| Key handling | wallet works out of the box | generate offline with `tools/keygen.py`, sign with `tools/sign.py` |

```bash
python tools/keygen.py --name "Ayesha Khan" --roll 2022-cs-101 > identity.json   # offline keypair
python tools/sign.py --identity identity.json --challenge <hex> --rp localhost:8080
```
Even in demo mode the server never uses a key of its own: `/api/sign` only signs a *live* challenge with a key supplied by the caller.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APEX_DEMO_MODE` | `0` (`1` in `run.sh`/compose) | Enable server-side keygen/sign |
| `SECRET_KEY` | random, persisted in data dir | Flask session signing key |
| `APEX_DATA_DIR` | `pqc-identity/db` | Databases, secrets |
| `APEX_RP_ID` | request host | Relying-party id bound into signatures |
| `APEX_UNI_DOMAIN` | `apex.edu` | Email domain for roll numbers |
| `OQS_LIB` | auto-detect | Path to `liboqs.so` |
| `HOST` / `PORT` | `127.0.0.1` / `8080` | Bind address |
| `COOKIE_SECURE`, `APEX_TRUST_PROXY` | off | Set both behind an HTTPS reverse proxy |
| `APEX_DEBUG` | off | Flask debugger (never enable on a network) |

## Architecture

```
Browser ── signup / login pages ──┐
Wallet (MV3, encrypted vault) ────┤   Flask (gunicorn, 1 worker)
                                  ├── models.py  SQLite: users, requests, challenges, audit log
                                  ├── pqc_engine.py  ctypes → liboqs ML-DSA-44
                                  └── ledger.py  3 SQLite replicas, SHA3-256 hash chain, 2/3 quorum
```

Login message: `apex-pq/login/v1 \n rp-id \n did \n challenge`. Binding the relying party and DID means a signature phished for another site, user or purpose does not verify here.

**Identifiers.** A DID is `did:key:z` + base58(`0x0c01` ‖ SHA3-256(pubkey)[:16]). It is a short hash commitment to the public key that is resolved through this registry; it is **not** a W3C-conformant, self-resolving `did:key`, which would embed the full 1312-byte key.

## API

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/signup` | none, 5/h/IP | Validates name, roll number, DID↔pubkey binding |
| `POST /api/challenge` | none, 20/min/IP | Single-use, 120 s |
| `POST /api/login` | none, 10/min/IP | Verify → atomic consume → session |
| `POST /api/admin/{approve,reject}/<id>`, `/revoke/<did>`, `/edit/<did>` | admin | Ledger-anchored; role whitelist; last admin protected |
| `GET /api/blockchain/node/<n>`, `/verify/<n>`, `GET /api/verify/identity` | login | |
| `POST /api/keygen`, `/api/sign` | demo mode only | See above |

## Testing
```bash
./run.sh test        # python -m unittest; uses real liboqs when loadable
```
The suite covers login success, replay, wrong key, relying-party binding, RBAC, CSRF origin checks, signup validation, approve/revoke flow, stored-XSS regression, and ledger tamper detection. CI (`.github/workflows/ci.yml`) builds liboqs from source and runs it.

## Threat model and known limitations

**In scope / mitigated:** credential theft from the server DB (only public keys stored), challenge replay, cross-site/cross-user signature reuse, session forgery (random secret), stored XSS via audit log, CSRF on state-changing routes, brute force (rate limits, wallet throttling), wallet-at-rest key theft (vault encryption), ledger tampering (hash chain + replicas).

**Not solved (be honest about these):**
- **Demo mode sends the secret key to the server.** A proper fix is ML-DSA in the browser/extension (e.g. a WASM build of liboqs or a vetted JS implementation). Until then use hardened mode with the offline tools.
- **The ledger is not BFT.** Three SQLite files in one process: replication and tamper-evidence, not consensus. An attacker with write access to a majority of files can rewrite history; blocks are not signed.
- **No proof-of-possession at signup**; the admin approval step is the gate.
- **Admin bootstrap key** is created on the server and must be imported then deleted.
- Single worker, in-memory rate limits, SQLite. No CSP (templates use inline scripts), no account recovery, no key rotation.
- Python cannot reliably wipe secret bytes from memory; liboqs calls are not hardened against side channels by this wrapper.
- Not independently audited.

## Roadmap
1. In-extension ML-DSA signing and keygen (remove demo mode).
2. Sign ledger blocks (admin key) and add real multi-process consensus (e.g. Raft).
3. Strict CSP, key rotation, passkey-style recovery.
4. Full `did:key` / DID-document resolution.

## Project layout
```
pqc-identity/   app.py models.py ledger.py pqc_engine.py config.py templates/ static/ tools/ tests/
  wallet-extension/   manifest.json popup.* background.js content.js
liboqs/         vendored liboqs source (consider a git submodule)
Dockerfile  docker-compose.yml  run.sh  .github/workflows/ci.yml
```

## Screenshots
Login · Signup · Admin dashboard · Ledger explorer — see `docs/images/`. (Captured before the 2.0 hardening; the wallet unlock screen now asks for a passphrase.)

## License
MIT — see [LICENSE](LICENSE). liboqs is MIT/Apache-2.0 licensed by the Open Quantum Safe project.

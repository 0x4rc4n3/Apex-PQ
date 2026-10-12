# Security policy

Apex-PQ is a **research prototype**. Please report vulnerabilities privately via a GitHub
security advisory on this repository rather than a public issue. See "Threat model and
known limitations" in the README for what is deliberately out of scope.

**Key rotation notice:** earlier revisions of this repository contained a committed admin
private key (`db/admin_did.json`, `wallet-extension/seeds.json`, and a comment in `app.py`).
Treat that identity as compromised. Never reuse it; delete any old `db/` directory and let
the app generate a fresh admin identity.

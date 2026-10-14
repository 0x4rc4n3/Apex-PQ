"""Run:  python -m unittest discover -s tests -v   (needs liboqs; see README)"""
import os, sys, tempfile, unittest

_TMP = tempfile.mkdtemp(prefix="apex-test-")
os.environ.update(APEX_DATA_DIR=_TMP, APEX_DEMO_MODE="1", SECRET_KEY="test-secret")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pqc_engine
USING_STUB = not pqc_engine.available()
if USING_STUB:
    # liboqs not loadable here: swap in a NON-SECURE stand-in so the application logic
    # (auth flow, replay, RBAC, ledger) is still exercised. Real crypto runs in CI/Docker.
    import hashlib, hmac, secrets
    _pk = lambda sk: hashlib.shake_256(sk).digest(pqc_engine.PK_LEN)
    def _gen():
        sk = secrets.token_bytes(pqc_engine.SK_LEN); pk = _pk(sk)
        return pqc_engine.derive_did(pk), pk.hex(), sk.hex()
    def _sig(pk, m): return hashlib.shake_256(hmac.new(pk, m, "sha256").digest()).digest(pqc_engine.SIG_LEN)
    pqc_engine.generate_keypair = _gen
    pqc_engine.sign_message = lambda sk_hex, m: _sig(_pk(bytes.fromhex(sk_hex)), m).hex()
    pqc_engine.verify_signature = lambda pk_hex, m, s: hmac.compare_digest(_sig(bytes.fromhex(pk_hex), m).hex(), s)
    print("NOTE: running with stub crypto backend (liboqs unavailable)")

import json, sqlite3
import app as appmod, ledger
from pqc_engine import generate_keypair, login_message, sign_message

ADMIN = json.load(open(appmod.ADMIN_SECRET_FILE))


def login(client, ident, rp="localhost"):
    ch = client.post("/api/challenge", json={"roll_no": ident["roll_no"]}).get_json()["challenge"]
    sig = sign_message(ident["privkey_hex"], login_message(ident["did"], ch, rp))
    return client.post("/api/login", json={"did": ident["did"], "challenge": ch, "signature": sig}), ch, sig


class Tests(unittest.TestCase):
    def setUp(self):
        self.c = appmod.app.test_client()

    def test_admin_key_file_is_private(self):
        self.assertEqual(os.stat(appmod.ADMIN_SECRET_FILE).st_mode & 0o077, 0)

    def test_no_server_held_key_signing(self):
        r = self.c.post("/api/challenge", json={"roll_no": "admin"}).get_json()
        r2 = self.c.post("/api/sign", json={"did": r["did"], "challenge": r["challenge"]})
        self.assertEqual(r2.status_code, 400)           # no privkey -> refused, no admin fallback

    def test_demo_roster_sync_and_login_for_all_four_accounts(self):
        from unittest.mock import patch
        response = self.c.get("/api/demo/accounts")
        self.assertEqual(response.status_code, 200)
        accounts = response.get_json()["accounts"]
        self.assertEqual({a["roll_no"] for a in accounts}, {"admin", "student1", "student2", "student3"})
        self.assertEqual(sum(a["role"] == "admin" for a in accounts), 1)
        self.assertTrue(all(a["demo_seed"] for a in accounts))
        with patch.object(appmod._limiter, "allow", return_value=True):
            for account in accounts:
                challenge = self.c.post("/api/challenge", json={"roll_no": account["roll_no"]}).get_json()
                signed = self.c.post("/api/sign", json={"did": account["did"],
                    "challenge": challenge["challenge"], "privkey_hex": account["privkey_hex"]}).get_json()
                logged_in = self.c.post("/api/login", json={"did": account["did"],
                    "challenge": challenge["challenge"], "signature": signed["signature"]})
                self.assertEqual(logged_in.status_code, 200, account["roll_no"])
                self.assertEqual(logged_in.get_json()["role"], account["role"])
            admin = next(a for a in accounts if a["role"] == "admin")
            admin_client = appmod.app.test_client()
            self.assertTrue(login(admin_client, admin)[0].get_json()["ok"])
            self.assertEqual(admin_client.post("/api/admin/revoke/" + admin["did"]).status_code, 400)
            student = next(a for a in accounts if a["roll_no"] == "student1")
            edited = admin_client.post("/api/admin/edit/" + student["did"], json={
                "full_name": "Updated Student One", "email": "student1@apex.edu", "role": "student"})
            self.assertEqual(edited.status_code, 200)
            synced = self.c.get("/api/demo/accounts").get_json()["accounts"]
            updated = next(a for a in synced if a["did"] == student["did"])
            self.assertEqual(updated["name"], "Updated Student One")

    def test_demo_roster_endpoint_is_disabled_outside_demo_mode(self):
        from unittest.mock import patch
        with patch.dict(appmod.app.config, {"DEMO_MODE": False}):
            self.assertEqual(self.c.get("/api/demo/accounts").status_code, 404)

    def test_seeds_endpoint_removed(self):
        self.assertEqual(self.c.get("/api/wallet/seeds").status_code, 404)

    def test_login_ok_and_replay_rejected(self):
        resp, ch, sig = login(self.c, ADMIN)
        self.assertTrue(resp.get_json()["ok"])
        again = self.c.post("/api/login", json={"did": ADMIN["did"], "challenge": ch, "signature": sig})
        self.assertEqual(again.status_code, 401)

    def test_signature_bound_to_rp(self):
        ch = self.c.post("/api/challenge", json={"roll_no": "admin"}).get_json()["challenge"]
        sig = sign_message(ADMIN["privkey_hex"], login_message(ADMIN["did"], ch, "evil.example"))
        r = self.c.post("/api/login", json={"did": ADMIN["did"], "challenge": ch, "signature": sig})
        self.assertEqual(r.status_code, 401)

    def test_wrong_key_rejected(self):
        _, _, other_sk = generate_keypair()
        ch = self.c.post("/api/challenge", json={"roll_no": "admin"}).get_json()["challenge"]
        sig = sign_message(other_sk, login_message(ADMIN["did"], ch, "localhost"))
        self.assertEqual(self.c.post("/api/login", json={"did": ADMIN["did"], "challenge": ch,
                                                         "signature": sig}).status_code, 401)

    def test_admin_routes_require_admin(self):
        self.assertIn(self.c.post("/api/admin/approve/1").status_code, (302, 403))
        self.assertEqual(self.c.get("/api/blockchain/node/0").status_code, 401)

    def test_cross_origin_post_blocked(self):
        r = self.c.post("/api/login", json={}, headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_signup_approve_flow_and_validation(self):
        did, pk, sk = generate_keypair()
        bad = self.c.post("/api/signup", json={"full_name": "A B", "roll_no": "admin", "did": did, "pubkey_hex": pk})
        self.assertEqual(bad.status_code, 400)                                   # reserved
        mism = self.c.post("/api/signup", json={"full_name": "A B", "roll_no": "s1x", "did": "did:key:zFake", "pubkey_hex": pk})
        self.assertEqual(mism.status_code, 400)                                  # DID != key
        ok = self.c.post("/api/signup", json={"full_name": "Sam Student", "roll_no": "s1x", "did": did, "pubkey_hex": pk})
        self.assertTrue(ok.get_json()["ok"])
        admin = appmod.app.test_client()
        self.assertTrue(login(admin, ADMIN)[0].get_json()["ok"])
        rid = appmod.get_pending_requests()[0]["id"]
        self.assertTrue(admin.post(f"/api/admin/approve/{rid}").get_json()["ok"])
        self.assertEqual(admin.post(f"/api/admin/approve/{rid}").status_code, 404)  # not twice
        student = {"roll_no": "s1x", "did": did, "privkey_hex": sk}
        s = appmod.app.test_client()
        self.assertEqual(login(s, student)[0].get_json()["role"], "student")
        self.assertEqual(s.post("/api/admin/revoke/" + did).status_code, 403)     # student can't revoke
        self.assertTrue(admin.post("/api/admin/revoke/" + did).get_json()["ok"])
        self.assertEqual(s.get("/dashboard").status_code, 302)                    # revoked -> kicked out

    def test_bootstrap_key_is_protected_and_single_use(self):
        from unittest.mock import patch
        path = os.path.join(_TMP, "bootstrap-once.json")
        key_data = {"role": "admin", "privkey_hex": "test-private-material"}
        with patch.object(appmod, "ADMIN_SECRET_FILE", path):
            with patch.dict(os.environ, {"APEX_BOOTSTRAP_TOKEN": ""}):
                self.assertEqual(self.c.get("/api/bootstrap/admin-key").status_code, 404)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(key_data, f)
            token = "t" * 48
            with patch.dict(os.environ, {"APEX_BOOTSTRAP_TOKEN": token}):
                self.assertEqual(self.c.get("/api/bootstrap/admin-key").status_code, 403)
                headers = {"Authorization": "Bearer " + token}
                response = self.c.get("/api/bootstrap/admin-key", headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), key_data)
                self.assertEqual(response.headers.get("Cache-Control"), "no-store, private")
                self.assertFalse(os.path.exists(path))
                self.assertEqual(self.c.get("/api/bootstrap/admin-key", headers=headers).status_code, 404)

    def test_pages_render_for_admin(self):
        admin = appmod.app.test_client()
        self.assertTrue(login(admin, ADMIN)[0].get_json()["ok"])
        for path in ("/admin", "/admin/logs", "/blockchain", "/verify?q=admin", "/info"):
            r = admin.get(path)
            self.assertEqual(r.status_code, 200, path)
        self.assertNotIn(b"copyToClipboard('", admin.get("/admin/logs").data)

    def test_log_xss_payload_is_inert(self):
        evil = "did:key:z'),alert(1),('"
        self.c.post("/api/login", json={"did": evil, "challenge": "x", "signature": "y"})
        admin = appmod.app.test_client(); login(admin, ADMIN)
        page = admin.get("/admin/logs").data.decode()
        self.assertNotIn("copyToClipboard('did:key:z'", page)

    def test_ledger_valid_and_tamper_detected(self):
        self.assertTrue(all(ledger.verify_chain(i)[0] for i in range(3)))
        db = sqlite3.connect(ledger.NODE_DBS[2])
        db.execute("UPDATE blocks SET data=? WHERE idx=1", ('{"action": "forged"}',)); db.commit(); db.close()
        self.assertFalse(ledger.verify_chain(2)[0])
        self.assertTrue(ledger.verify_chain(0)[0])


if __name__ == "__main__":
    unittest.main()

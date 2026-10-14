"""
app.py — Apex-PQ identity portal (Flask).

Authentication = ML-DSA-44 signature over a server challenge. There are no
passwords. See README.md for the threat model and known limitations.
"""
import contextlib
import datetime
import functools
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

import ledger
from config import BASE_DIR, DATA_DIR, UNI_DOMAIN, env_flag
from ledger import NODE_NAMES, add_block, get_block_by_did, get_chain, get_ledger_stats, verify_chain
from models import (ROLES, approve_request, challenge_is_live,
                    consume_challenge, count_admins, create_challenge, create_signup_request,
                    create_user, delete_user, email_to_roll, get_all_events, get_all_users,
                    get_pending_requests, get_recent_events, get_request, get_user_by_did,
                    get_user_by_email, get_user_by_roll_no, init_db, log_event, reject_request,
                    roll_to_email, update_last_login, update_user, valid_roll_no, RESERVED)
from pqc_engine import (did_matches_pubkey, generate_keypair, login_message,
                        sign_message, verify_signature)

# ── App & configuration ──────────────────────────────────────────────────────

app = Flask(__name__)
app.config.update(
    DEMO_MODE=env_flag("APEX_DEMO_MODE", False),   # enables /api/keygen and /api/sign
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_flag("COOKIE_SECURE", False),
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=2),
    MAX_CONTENT_LENGTH=64 * 1024,
)
if env_flag("APEX_TRUST_PROXY"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _load_secret_key() -> str:
    """SECRET_KEY from env, else a random key generated once and kept (0600) in the data dir."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "secret_key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app.secret_key = _load_secret_key()

# ── Rate limiting (Redis-backed with in-process fallback) ──────────────────────

class RateLimiter:
    def __init__(self):
        self._hits, self._lock = defaultdict(deque), threading.Lock()
        self._redis = None
        redis_url = os.environ.get("REDIS_URL")
        if redis_url:
            try:
                import redis
                self._redis = redis.from_url(redis_url, socket_timeout=2)
                self._redis.ping()
            except Exception as e:
                print(f"[RateLimiter] Redis unavailable ({e}); falling back to in-memory limiter.")
                self._redis = None

    def allow(self, key: str, limit: int, window: int) -> bool:
        if self._redis:
            try:
                now = time.time()
                rkey = f"apex:rate:{key}"
                pipe = self._redis.pipeline()
                pipe.zremrangebyscore(rkey, 0, now - window)
                pipe.zcard(rkey)
                pipe.zadd(rkey, {f"{now}:{secrets.token_hex(4)}": now})
                pipe.expire(rkey, window + 5)
                _, count, _, _ = pipe.execute()
                return count < limit
            except Exception:
                pass  # Fall back to in-process limiter on Redis blip
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


_limiter = RateLimiter()
_admin_lock = threading.Lock()


@contextlib.contextmanager
def distributed_lock(name: str, timeout: float = 10.0):
    """Distributed lock when REDIS_URL is configured, else process-level lock."""
    r_client = _limiter._redis
    if r_client:
        lock = r_client.lock(f"apex:lock:{name}", timeout=timeout)
        acquired = lock.acquire(blocking=True, blocking_timeout=timeout)
        if not acquired:
            raise RuntimeError(f"Could not acquire lock for {name}")
        try:
            yield
        finally:
            try:
                lock.release()
            except Exception:
                pass
    else:
        with _admin_lock:
            yield


def rate_limited(name, limit, window):
    def deco(f):
        @functools.wraps(f)
        def wrapper(*a, **kw):
            if not _limiter.allow(f"{name}:{request.remote_addr}", limit, window):
                return jsonify({"ok": False, "error": "Too many requests. Slow down."}), 429
            return f(*a, **kw)
        return wrapper
    return deco


# ── Request hooks ────────────────────────────────────────────────────────────

_EXT_ALLOWED_PATHS = {"/api/sign", "/api/keygen"}   # the wallet popup calls these


@app.before_request
def setup_request():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.before_request
def csrf_origin_check():
    """Reject cross-origin state-changing requests (defence in depth on top of SameSite=Lax)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    origin = request.headers.get("Origin")
    if not origin:
        return None                      # non-browser client
    if urlparse(origin).netloc == request.host:
        return None
    if origin.startswith("chrome-extension://") and request.path in _EXT_ALLOWED_PATHS:
        return None
    return jsonify({"ok": False, "error": "Cross-origin request blocked."}), 403


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    nonce = getattr(g, "csp_nonce", "")
    nonce_part = f"'nonce-{nonce}'" if nonce else ""
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' {nonce_part}; "
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"font-src 'self' https://fonts.gstatic.com; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none';"
    )
    resp.headers["Content-Security-Policy"] = csp
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.context_processor
def inject_flags():
    return {
        "demo_mode": app.config["DEMO_MODE"],
        "me": current_user(),
        "csp_nonce": getattr(g, "csp_nonce", ""),
    }


def rp_id() -> str:
    """Relying-party identifier bound into every login signature."""
    return os.environ.get("APEX_RP_ID") or request.host


# ── Jinja filters ────────────────────────────────────────────────────────────

@app.template_filter("ts_to_dt")
def ts_to_dt(ts):
    if not ts:
        return "—"
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)


@app.template_filter("truncate_hex")
def truncate_hex(hex_str, head=8, tail=8):
    if not hex_str or len(hex_str) <= head + tail + 3:
        return hex_str or "—"
    return f"{hex_str[:head]}…{hex_str[-tail:]}"


@app.template_filter("truncate_did")
def truncate_did(did, head=20, tail=8):
    if not did:
        return "—"
    return did if len(did) <= head + tail + 3 else f"{did[:head]}…{did[-tail:]}"


# ── Bootstrap ────────────────────────────────────────────────────────────────

ADMIN_PUBLIC_FILE = os.path.join(DATA_DIR, "admin_public.json")
ADMIN_SECRET_FILE = os.path.join(DATA_DIR, "ADMIN_KEY_IMPORT_THEN_DELETE.json")


def bootstrap():
    init_db()
    ledger.init_ledger()
    _ensure_admin()


def _write_private(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=2)


def _ensure_admin():
    if os.path.exists(ADMIN_PUBLIC_FILE):
        with open(ADMIN_PUBLIC_FILE) as f:
            info = json.load(f)
        if not get_user_by_did(info["did"]):
            create_user(info["did"], info["email"], info["full_name"], None,
                        info["pubkey_hex"], role="admin")
        return

    did, pubkey_hex, privkey_hex = generate_keypair()
    email = roll_to_email("admin")
    _write_private(ADMIN_PUBLIC_FILE, {"did": did, "pubkey_hex": pubkey_hex, "email": email,
                                       "full_name": "System Administrator"})
    # Wallet-import format. Written ONCE, mode 0600; the server never reads it again.
    _write_private(ADMIN_SECRET_FILE, {"name": "System Administrator", "roll_no": "admin",
                                       "email": email, "role": "admin", "did": did,
                                       "pubkey_hex": pubkey_hex, "privkey_hex": privkey_hex})
    create_user(did, email, "System Administrator", None, pubkey_hex, role="admin")
    try:
        add_block({"action": "register_admin", "did": did, "email": email,
                   "name": "System Administrator", "pubkey": pubkey_hex[:16] + "…"})
    except Exception as e:
        print(f"[Ledger] Admin anchor failed: {e}")
    print(f"\n[PQC-ID] First run — admin identity created.\n"
          f"  DID : {did}\n"
          f"  Key : {ADMIN_SECRET_FILE}\n"
          f"  Import it into the Apex wallet, then DELETE that file.\n")


# ── Auth helpers ─────────────────────────────────────────────────────────────

def current_user():
    """Authoritative user row for the session (role comes from the DB, never the cookie)."""
    did = session.get("did")
    return get_user_by_did(did) if did else None


def login_required(f):
    @functools.wraps(f)
    def decorated(*a, **kw):
        if not current_user():
            session.clear()
            return redirect(url_for("login_page"))
        return f(*a, **kw)
    return decorated


def admin_required(f):
    @functools.wraps(f)
    def decorated(*a, **kw):
        user = current_user()
        if not user or user["role"] != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Admin authentication required."}), 403
            return redirect(url_for("login_page"))
        return f(*a, **kw)
    return decorated


def api_login_required(f):
    @functools.wraps(f)
    def decorated(*a, **kw):
        if not current_user():
            return jsonify({"ok": False, "error": "Authentication required."}), 401
        return f(*a, **kw)
    return decorated


# ── Pages ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    user = current_user()
    if user:
        return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "student_dashboard"))
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/login")
def login_page():
    return redirect(url_for("index")) if current_user() else render_template("login.html")


@app.route("/signup")
def signup_page():
    return redirect(url_for("index")) if current_user() else render_template("signup.html")


@app.route("/pending")
def pending_page():
    return render_template("pending.html", did=request.args.get("did", "")[:120])


@app.route("/info")
@login_required
def info_page():
    return render_template("info.html")


@app.route("/dashboard")
@login_required
def student_dashboard():
    return render_template("dashboard_student.html", user=current_user())


@app.route("/admin/logs")
@admin_required
def admin_logs():
    logs = get_all_events()
    stats = {
        "total":   len(logs),
        "success": sum(1 for l in logs if l["event"] == "login_ok"),
        "failed":  sum(1 for l in logs if l["event"] == "login_fail"),
        "admin":   sum(1 for l in logs if l["event"] in ("approved", "rejected", "keygen")),
    }
    auth_total = stats["success"] + stats["failed"]
    stats["rate"] = round(stats["success"] / auth_total * 100, 1) if auth_total else 0
    return render_template("admin_logs.html", logs=logs, stats=stats)


@app.route("/admin")
@admin_required
def admin_dashboard():
    return render_template("dashboard_admin.html", pending=get_pending_requests(),
                           users=get_all_users(), log=get_recent_events(20),
                           ledger_stats=get_ledger_stats(), admin=current_user())


@app.route("/verify")
@login_required
def verify_page():
    query, result, chain_block, err = request.args.get("q", "").strip()[:200], None, None, None
    if query:
        user = (get_user_by_did(query) if query.startswith("did:")
                else get_user_by_roll_no(query) or get_user_by_email(query))
        if not user:
            err = f"No identity found for '{query}'"
        else:
            chain_block, result = get_block_by_did(user["did"]), user
    return render_template("verify.html", query=query, result=result,
                           chain_block=chain_block, err=err)


@app.route("/blockchain")
@login_required
def blockchain_page():
    chains = []
    for i in range(3):
        chain = get_chain(i)
        valid, msg, _ = verify_chain(i)
        chains.append({"node": i, "name": NODE_NAMES[i], "chain": list(reversed(chain)),
                       "valid": valid, "status": msg, "count": len(chain)})
    return render_template("blockchain.html", chains=chains, stats=get_ledger_stats())


@app.route("/logout", methods=["POST"])
def logout():
    log_event("logout", did=session.get("did"), ip=request.remote_addr)
    session.clear()
    return redirect(url_for("login_page"))


# ── API: demo-only helpers (server-side keygen / signing) ────────────────────
# A browser/extension cannot yet run ML-DSA locally in this project, so the demo
# generates and signs on the server. That is fine on localhost and WRONG in
# production, hence off unless APEX_DEMO_MODE=1. Use tools/keygen.py and
# tools/sign.py to keep secret keys off the server entirely.

def _demo_only(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if not app.config["DEMO_MODE"]:
            return jsonify({"ok": False, "error": "Disabled. Set APEX_DEMO_MODE=1 or use tools/keygen.py."}), 404
        return f(*a, **kw)
    return wrapper


@app.route("/api/keygen", methods=["POST"])
@_demo_only
@rate_limited("keygen", 10, 60)
def api_keygen():
    try:
        did, pubkey_hex, privkey_hex = generate_keypair()
    except Exception:
        return jsonify({"ok": False, "error": "Key generation failed."}), 500
    log_event("keygen", ip=request.remote_addr)
    return jsonify({"ok": True, "did": did, "pubkey_hex": pubkey_hex, "privkey_hex": privkey_hex})


@app.route("/api/sign", methods=["POST"])
@_demo_only
@rate_limited("sign", 20, 60)
def api_sign():
    """Signs a *live login challenge* with a caller-supplied key. Never uses a server-held key."""
    data = request.get_json(silent=True) or {}
    did, challenge, sk = (str(data.get(k, "")).strip() for k in ("did", "challenge", "privkey_hex"))
    if not (did and challenge and sk):
        return jsonify({"ok": False, "error": "did, challenge and privkey_hex are required."}), 400
    if not challenge_is_live(challenge, did):
        return jsonify({"ok": False, "error": "Challenge invalid or expired."}), 400
    try:
        sig = sign_message(sk, login_message(did, challenge, rp_id()))
    except (ValueError, RuntimeError):
        return jsonify({"ok": False, "error": "Signing failed (bad key?)."}), 400
    return jsonify({"ok": True, "signature": sig})


# ── API: signup / login ──────────────────────────────────────────────────────

@app.route("/api/signup", methods=["POST"])
@rate_limited("signup", 5, 3600)
def api_signup():
    data = request.get_json(silent=True) or {}
    full_name  = " ".join(str(data.get("full_name", "")).split())
    roll_no    = str(data.get("roll_no", "")).strip().lower()
    did        = str(data.get("did", "")).strip()
    pubkey_hex = str(data.get("pubkey_hex", "")).strip().lower()

    if not (2 <= len(full_name) <= 80) or not full_name.isprintable():
        return jsonify({"ok": False, "error": "Enter a valid full name (2–80 characters)."}), 400
    if not valid_roll_no(roll_no) or roll_no in RESERVED:
        return jsonify({"ok": False, "error": "Invalid roll number."}), 400
    if not did_matches_pubkey(did, pubkey_hex):
        return jsonify({"ok": False, "error": "DID does not match the supplied public key."}), 400

    email = roll_to_email(roll_no)
    ok, err = create_signup_request(full_name, email, roll_no, did, pubkey_hex, roll_no=roll_no)
    if not ok:
        return jsonify({"ok": False, "error": err}), 409
    log_event("signup_request", did=did, ip=request.remote_addr, detail=f"{full_name} <{email}>")
    return jsonify({"ok": True, "email": email, "message": "Request submitted. Awaiting admin approval."})


@app.route("/api/challenge", methods=["POST"])
@rate_limited("challenge", 20, 60)
def api_challenge():
    data = request.get_json(silent=True) or {}
    roll_no, did = str(data.get("roll_no", "")).strip().lower(), str(data.get("did", "")).strip()
    if roll_no:
        user = get_user_by_roll_no(roll_no)
    elif did:
        user = get_user_by_did(did)
    else:
        return jsonify({"ok": False, "error": "Provide roll_no or did."}), 400
    if not user:
        return jsonify({"ok": False, "error": "Identity not found or not approved."}), 404
    return jsonify({"ok": True, "challenge": create_challenge(user["did"], ttl=120),
                    "did": user["did"], "name": user["full_name"], "email": user["email"],
                    "rp": rp_id(), "ttl": 120})


@app.route("/api/login", methods=["POST"])
@rate_limited("login", 10, 60)
def api_login():
    data = request.get_json(silent=True) or {}
    did, challenge, sig_hex = (str(data.get(k, "")).strip() for k in ("did", "challenge", "signature"))
    if not (did and challenge and sig_hex):
        return jsonify({"ok": False, "error": "DID, challenge, and signature required."}), 400

    user = get_user_by_did(did)
    if not user:
        log_event("login_fail", did=did, ip=request.remote_addr, detail="unknown DID")
        return jsonify({"ok": False, "error": "Authentication failed."}), 401
    if not challenge_is_live(challenge, did):
        log_event("login_fail", did=did, ip=request.remote_addr, detail="bad/expired challenge")
        return jsonify({"ok": False, "error": "Challenge invalid or expired."}), 401
    if not verify_signature(user["pubkey_hex"], login_message(did, challenge, rp_id()), sig_hex):
        log_event("login_fail", did=did, ip=request.remote_addr, detail="bad signature")
        return jsonify({"ok": False, "error": "Signature verification failed."}), 401
    if not consume_challenge(challenge, did):          # single use, race-safe
        log_event("login_fail", did=did, ip=request.remote_addr, detail="challenge replay")
        return jsonify({"ok": False, "error": "Challenge invalid or expired."}), 401

    session.clear()
    session.permanent = True
    session["did"] = did
    update_last_login(did)
    log_event("login_ok", did=did, ip=request.remote_addr)
    return jsonify({"ok": True, "role": user["role"],
                    "redirect": url_for("admin_dashboard" if user["role"] == "admin" else "student_dashboard")})


# ── API: admin ───────────────────────────────────────────────────────────────

@app.route("/api/admin/approve/<int:req_id>", methods=["POST"])
@admin_required
def api_approve(req_id):
    admin = current_user()
    with distributed_lock("admin_approve"):
        req = get_request(req_id)
        if not req or req["status"] != "pending":
            return jsonify({"ok": False, "error": "Request not found or already processed."}), 404
        try:      # ledger first: never activate an identity that isn't anchored
            add_block({"action": "register", "did": req["did"], "name": req["full_name"],
                       "email": req["email"], "roll_no": req.get("roll_no") or email_to_roll(req["email"]),
                       "pubkey": req["pubkey_hex"][:16] + "…", "approved_by": admin["did"][:20] + "…"})
        except RuntimeError as e:
            return jsonify({"ok": False, "error": f"Ledger unavailable: {e}"}), 503
        if not approve_request(req_id, admin["did"]):
            return jsonify({"ok": False, "error": "Could not activate user."}), 409
    log_event("approved", did=req["did"], ip=request.remote_addr, detail=req["email"])
    return jsonify({"ok": True, "did": req["did"], "email": req["email"]})


@app.route("/api/admin/reject/<int:req_id>", methods=["POST"])
@admin_required
def api_reject(req_id):
    req = reject_request(req_id, current_user()["did"])
    if not req:
        return jsonify({"ok": False, "error": "Request not found or already processed."}), 404
    log_event("rejected", did=req["did"], ip=request.remote_addr, detail=req["email"])
    return jsonify({"ok": True})


@app.route("/api/admin/revoke/<path:did>", methods=["POST"])
@admin_required
def api_revoke(did):
    admin = current_user()
    if did == admin["did"]:
        return jsonify({"ok": False, "error": "Cannot revoke yourself."}), 400
    user = get_user_by_did(did)
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user["role"] == "admin":
        return jsonify({"ok": False, "error": "Cannot revoke an admin."}), 400
    with distributed_lock("admin_revoke"):
        try:
            add_block({"action": "revoke", "did": did, "email": user["email"],
                       "revoked_by": admin["did"][:20] + "…"})
        except RuntimeError as e:
            return jsonify({"ok": False, "error": f"Ledger unavailable: {e}"}), 503
        if not delete_user(did):
            return jsonify({"ok": False, "error": "Failed to revoke user."}), 500
    log_event("revoked", did=did, ip=request.remote_addr, detail=user["email"])
    return jsonify({"ok": True})


@app.route("/api/admin/edit/<path:did>", methods=["POST"])
@admin_required
def api_edit_user(did):
    admin = current_user()
    data = request.get_json(silent=True) or {}
    full_name = " ".join(str(data.get("full_name", "")).split())
    email     = str(data.get("email", "")).strip().lower()
    role      = str(data.get("role", "student")).strip()

    local, _, domain = email.partition("@")
    if not (2 <= len(full_name) <= 80) or not valid_roll_no(local) or domain != UNI_DOMAIN:
        return jsonify({"ok": False, "error": f"Name and a valid @{UNI_DOMAIN} email are required."}), 400
    if role not in ROLES:
        return jsonify({"ok": False, "error": "Invalid role."}), 400
    user = get_user_by_did(did)
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if user["role"] != role:
        if did == admin["did"]:
            return jsonify({"ok": False, "error": "You cannot change your own role."}), 400
        if user["role"] == "admin" and count_admins() <= 1:
            return jsonify({"ok": False, "error": "Cannot demote the last admin."}), 400
    with distributed_lock("admin_edit"):
        try:
            add_block({"action": "edit_user", "did": did, "email": email, "role": role,
                       "edited_by": admin["did"][:20] + "…"})
        except RuntimeError as e:
            return jsonify({"ok": False, "error": f"Ledger unavailable: {e}"}), 503
        if not update_user(did, full_name, email, role):
            return jsonify({"ok": False, "error": "Email already in use or update failed."}), 400
    log_event("edited_user", did=did, ip=request.remote_addr, detail=email)
    return jsonify({"ok": True})


# ── API: ledger & verification (login required) ──────────────────────────────

@app.route("/api/blockchain/node/<int:node_id>")
@api_login_required
def api_blockchain_node(node_id):
    if node_id not in range(3):
        return jsonify({"ok": False, "error": "Node 0–2 only"}), 400
    valid, msg, _ = verify_chain(node_id)
    return jsonify({"ok": True, "node": node_id, "name": NODE_NAMES[node_id],
                    "blocks": list(reversed(get_chain(node_id))), "valid": valid, "status": msg})


@app.route("/api/blockchain/verify/<int:node_id>")
@api_login_required
def api_verify_node(node_id):
    if node_id not in range(3):
        return jsonify({"ok": False, "error": "Node 0–2 only"}), 400
    valid, msg, n = verify_chain(node_id)
    node = get_ledger_stats()[node_id]
    return jsonify({"ok": True, "valid": valid, "message": msg, "checked": n,
                    "blocks": node["blocks"], "tip": node["tip"],
                    "in_sync": ledger.consensus_status()["in_sync"]})


@app.route("/api/verify/identity")
@api_login_required
@rate_limited("verify", 30, 60)
def api_verify_identity():
    q = request.args.get("q", "").strip()[:200]
    if not q:
        return jsonify({"ok": False, "error": "q param required"}), 400
    user = (get_user_by_did(q) if q.startswith("did:")
            else get_user_by_roll_no(q) or get_user_by_email(q))
    if not user:
        return jsonify({"ok": True, "found": False, "message": "Identity not found"})
    blk = get_block_by_did(user["did"])
    return jsonify({"ok": True, "found": True, "name": user["full_name"], "role": user["role"],
                    "did": user["did"], "on_chain": blk is not None, "block": blk})


@app.route("/api/bootstrap/admin-key", methods=["GET"])
def bootstrap_admin_key():
    """Return and erase the bootstrap wallet file once, only with a deployment secret."""
    token = os.environ.get("APEX_BOOTSTRAP_TOKEN", "")
    if not token:
        return jsonify({"ok": False, "error": "Not found"}), 404
    supplied = request.headers.get("Authorization", "")
    if not secrets.compare_digest(supplied, f"Bearer {token}"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    with _admin_lock:
        if not os.path.isfile(ADMIN_SECRET_FILE):
            return jsonify({"ok": False, "error": "Bootstrap key already retrieved"}), 404
        try:
            with open(ADMIN_SECRET_FILE, encoding="utf-8") as f:
                key_data = json.load(f)
            os.remove(ADMIN_SECRET_FILE)
        except (OSError, json.JSONDecodeError):
            app.logger.exception("Unable to read bootstrap key")
            return jsonify({"ok": False, "error": "Bootstrap key unavailable"}), 500
    response = jsonify(key_data)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return response


# ── Entrypoint ───────────────────────────────────────────────────────────────

bootstrap()   # runs under gunicorn as well as `python app.py`

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    print(f"\n[PQC-ID] http://{host}:{port}  (demo mode: {app.config['DEMO_MODE']})\n")
    app.run(host=host, port=port, debug=env_flag("APEX_DEBUG", False))

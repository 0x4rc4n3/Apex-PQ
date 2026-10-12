"""
models.py — SQLite data layer (no ORM, all queries parameterised).
"""
import os
import re
import secrets
import sqlite3
import time

from config import DATA_DIR, UNI_DOMAIN

DB_PATH = os.path.join(DATA_DIR, "identity.db")

ROLES        = ("student", "admin")
ROLL_RE      = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
RESERVED     = {"admin", "root", "system", "administrator"}
MAX_ACTIVE_CHALLENGES = 5


def roll_to_email(roll_no: str) -> str:
    return f"{roll_no.strip().lower()}@{UNI_DOMAIN}"


def email_to_roll(email: str) -> str:
    return email.split("@")[0]


def valid_roll_no(roll_no: str) -> bool:
    return bool(ROLL_RE.match(roll_no or ""))


def get_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS signup_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE, roll_no TEXT, student_id TEXT NOT NULL,
            did TEXT NOT NULL UNIQUE, pubkey_hex TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL,
            reviewed_at INTEGER, reviewed_by TEXT);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL, student_id TEXT,
            role TEXT NOT NULL DEFAULT 'student', pubkey_hex TEXT NOT NULL,
            created_at INTEGER NOT NULL, last_login INTEGER);
        CREATE TABLE IF NOT EXISTS challenges (
            challenge_hex TEXT PRIMARY KEY, did TEXT NOT NULL, created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, did TEXT,
            ip TEXT, detail TEXT, ts INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_challenges_did ON challenges(did);
    """)
    db.commit()
    db.close()


def _one(query, args=()):
    db = get_db()
    try:
        row = db.execute(query, args).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def _all(query, args=()):
    db = get_db()
    try:
        return [dict(r) for r in db.execute(query, args).fetchall()]
    finally:
        db.close()


# ── Signup requests ──────────────────────────────────────────────────────────

def create_signup_request(full_name, email, student_id, did, pubkey_hex, roll_no=None):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO signup_requests (full_name, email, roll_no, student_id, did, pubkey_hex,"
            " status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
            (full_name, email, roll_no or email_to_roll(email), student_id, did, pubkey_hex,
             int(time.time())))
        db.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Roll number or DID already registered."
    finally:
        db.close()


def get_request(request_id):
    return _one("SELECT * FROM signup_requests WHERE id=?", (request_id,))


def get_pending_requests():
    return _all("SELECT * FROM signup_requests WHERE status='pending' ORDER BY created_at DESC")


def get_all_requests():
    return _all("SELECT * FROM signup_requests ORDER BY created_at DESC")


def approve_request(request_id, reviewer):
    """Atomically: pending -> approved and create the user. Returns the request or None."""
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        req = db.execute("SELECT * FROM signup_requests WHERE id=? AND status='pending'",
                         (request_id,)).fetchone()
        if not req:
            db.rollback()
            return None
        now = int(time.time())
        db.execute("INSERT INTO users (did, email, full_name, student_id, role, pubkey_hex, created_at)"
                   " VALUES (?, ?, ?, ?, 'student', ?, ?)",
                   (req["did"], req["email"], req["full_name"], req["student_id"],
                    req["pubkey_hex"], now))
        db.execute("UPDATE signup_requests SET status='approved', reviewed_at=?, reviewed_by=? WHERE id=?",
                   (now, reviewer, request_id))
        db.commit()
        return dict(req)
    except sqlite3.IntegrityError:
        db.rollback()
        return None
    finally:
        db.close()


def reject_request(request_id, reviewer):
    db = get_db()
    try:
        cur = db.execute("UPDATE signup_requests SET status='rejected', reviewed_at=?, reviewed_by=?"
                         " WHERE id=? AND status='pending'", (int(time.time()), reviewer, request_id))
        db.commit()
        return get_request(request_id) if cur.rowcount else None
    finally:
        db.close()


# ── Users ────────────────────────────────────────────────────────────────────

def create_user(did, email, full_name, student_id, pubkey_hex, role="student"):
    if role not in ROLES:
        return False
    db = get_db()
    try:
        db.execute("INSERT INTO users (did, email, full_name, student_id, role, pubkey_hex, created_at)"
                   " VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (did, email, full_name, student_id, role, pubkey_hex, int(time.time())))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        db.close()


def get_user_by_did(did):
    return _one("SELECT * FROM users WHERE did=?", (did,))


def get_user_by_email(email):
    return _one("SELECT * FROM users WHERE email=?", (email.lower(),))


def get_user_by_roll_no(roll_no):
    return get_user_by_email(roll_to_email(roll_no))


def get_user_by_student_id(student_id):
    return _one("SELECT * FROM users WHERE student_id=?", (student_id,))


def get_all_users():
    return _all("SELECT * FROM users ORDER BY created_at DESC")


def count_admins():
    return _one("SELECT COUNT(*) AS n FROM users WHERE role='admin'")["n"]


def update_user(did, full_name, email, role):
    if role not in ROLES:
        return False
    db = get_db()
    try:
        cur = db.execute("UPDATE users SET full_name=?, email=?, role=? WHERE did=?",
                         (full_name, email.lower(), role, did))
        db.commit()
        return cur.rowcount == 1
    except sqlite3.IntegrityError:
        return False
    finally:
        db.close()


def delete_user(did):
    """Revoke: remove the user and any outstanding challenges."""
    db = get_db()
    try:
        db.execute("DELETE FROM challenges WHERE did=?", (did,))
        cur = db.execute("DELETE FROM users WHERE did=?", (did,))
        db.commit()
        return cur.rowcount == 1
    except sqlite3.Error:
        return False
    finally:
        db.close()


def update_last_login(did):
    db = get_db()
    db.execute("UPDATE users SET last_login=? WHERE did=?", (int(time.time()), did))
    db.commit()
    db.close()


# ── Challenges ───────────────────────────────────────────────────────────────

def create_challenge(did, ttl=120):
    challenge, now = secrets.token_hex(32), int(time.time())
    db = get_db()
    try:
        db.execute("DELETE FROM challenges WHERE expires_at<? OR used=1", (now,))
        # keep only the newest few live challenges so one DID cannot be flooded
        db.execute("DELETE FROM challenges WHERE did=? AND challenge_hex NOT IN ("
                   " SELECT challenge_hex FROM challenges WHERE did=? ORDER BY created_at DESC LIMIT ?)",
                   (did, did, MAX_ACTIVE_CHALLENGES - 1))
        db.execute("INSERT INTO challenges VALUES (?, ?, ?, ?, 0)", (challenge, did, now, now + ttl))
        db.commit()
    finally:
        db.close()
    return challenge


def challenge_is_live(challenge_hex, did):
    return _one("SELECT 1 AS ok FROM challenges WHERE challenge_hex=? AND did=? AND used=0"
                " AND expires_at>?", (challenge_hex, did, int(time.time()))) is not None


def consume_challenge(challenge_hex, did):
    """Atomic single-use: True for exactly one caller."""
    db = get_db()
    try:
        cur = db.execute("UPDATE challenges SET used=1 WHERE challenge_hex=? AND did=? AND used=0"
                         " AND expires_at>?", (challenge_hex, did, int(time.time())))
        db.commit()
        return cur.rowcount == 1
    finally:
        db.close()


# ── Audit log ────────────────────────────────────────────────────────────────

def log_event(event, did=None, ip=None, detail=None):
    db = get_db()
    try:
        db.execute("INSERT INTO audit_log (event, did, ip, detail, ts) VALUES (?, ?, ?, ?, ?)",
                   (event, (did or None) and did[:200], ip, (detail or None) and detail[:500],
                    int(time.time())))
        db.commit()
    finally:
        db.close()


def get_recent_events(limit=50):
    return _all("SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?", (limit,))


def get_all_events(limit=5000):
    return _all("SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?", (limit,))

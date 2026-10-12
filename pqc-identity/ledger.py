"""
ledger.py — 3-replica append-only identity ledger (SHA3-256 hash chain).

HONEST SCOPE: the three "nodes" are three SQLite files written by one
process. This gives replication and tamper-evidence (hash chain + cross-node
tip comparison + 2-of-3 write quorum). It is NOT Byzantine fault tolerant:
there is no networking, no leader election and no consensus protocol.
"""
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import Counter

from config import DATA_DIR

NODE_DBS   = [os.path.join(DATA_DIR, f"node{i}.db") for i in range(3)]
NODE_NAMES = ["Node 0 — Primary", "Node 1 — Secondary", "Node 2 — Replica"]
GENESIS_TS = 1745000000
ZERO_HASH  = "0" * 64

_lock = threading.RLock()


def _block_hash(index, ts, data_str, prev_hash):
    return hashlib.sha3_256(f"{index}:{ts}:{data_str}:{prev_hash}".encode()).hexdigest()


def _connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    return db


def _genesis():
    data_str = json.dumps({"action": "genesis", "network": "apex-pq"}, sort_keys=True)
    return (0, GENESIS_TS, data_str, ZERO_HASH, _block_hash(0, GENESIS_TS, data_str, ZERO_HASH))


def init_ledger():
    os.makedirs(DATA_DIR, exist_ok=True)
    with _lock:
        for path in NODE_DBS:
            db = _connect(path)
            db.execute("""CREATE TABLE IF NOT EXISTS blocks (
                idx INTEGER PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL,
                prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)""")
            if db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0:
                db.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)", _genesis())
            db.commit()
            db.close()


def _tip(path):
    try:
        db = _connect(path)
        row = db.execute("SELECT idx, hash FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
        db.close()
        return tuple(row) if row else None
    except sqlite3.Error:
        return None


def _rows_after(path, idx):
    db = _connect(path)
    rows = db.execute("SELECT idx, ts, data, prev_hash, hash FROM blocks WHERE idx > ? ORDER BY idx",
                      (idx,)).fetchall()
    db.close()
    return rows


def _catch_up(src_path, dst_path, dst_tip):
    """Bring a node that is a strict prefix of the majority chain up to date."""
    try:
        db = _connect(dst_path)
        for row in _rows_after(src_path, dst_tip[0]):
            db.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)", row)
        db.commit()
        db.close()
    except sqlite3.Error as e:
        print(f"[Ledger] catch-up failed for {dst_path}: {e}")


def add_block(data: dict) -> dict:
    """Append a block. Requires 2-of-3 replicas to agree on the current tip and to accept the write."""
    ts, data_str = int(time.time()), json.dumps(data, sort_keys=True)
    with _lock:
        tips = [_tip(p) for p in NODE_DBS]
        counts = Counter(t for t in tips if t is not None)
        if not counts:
            raise RuntimeError("Ledger unavailable")
        tip, n = counts.most_common(1)[0]
        if n < 2:
            raise RuntimeError("Quorum failure: replicas disagree on the chain tip")

        src = NODE_DBS[tips.index(tip)]
        for i, t in enumerate(tips):
            if t is not None and t != tip and t[0] < tip[0]:
                _catch_up(src, NODE_DBS[i], t)
        tips = [_tip(p) for p in NODE_DBS]

        new_idx, prev_hash = tip[0] + 1, tip[1]
        h = _block_hash(new_idx, ts, data_str, prev_hash)
        written = 0
        for path, t in zip(NODE_DBS, tips):
            if t != tip:
                print(f"[Ledger] skipping diverged replica {path}")
                continue
            try:
                db = _connect(path)
                db.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
                           (new_idx, ts, data_str, prev_hash, h))
                db.commit()
                db.close()
                written += 1
            except sqlite3.Error as e:
                print(f"[Ledger] write error on {path}: {e}")
        if written < 2:
            raise RuntimeError(f"Quorum failure: only {written}/3 replicas accepted the block")
        return {"index": new_idx, "ts": ts, "data": data, "prev_hash": prev_hash, "hash": h}


def get_chain(node_idx: int) -> list:
    db = _connect(NODE_DBS[node_idx])
    rows = db.execute("SELECT idx, ts, data, prev_hash, hash FROM blocks ORDER BY idx").fetchall()
    db.close()
    return [{"index": r[0], "ts": r[1], "data": json.loads(r[2]), "prev_hash": r[3], "hash": r[4]}
            for r in rows]


def get_block_by_did(did: str):
    """First block mentioning this DID, searched on the first healthy replica."""
    for i in range(3):
        try:
            for blk in get_chain(i):
                if blk["data"].get("did") == did:
                    return {**blk, "node": i}
            return None
        except sqlite3.Error:
            continue
    return None


def verify_chain(node_idx: int) -> tuple:
    """Returns (is_valid, message, checked_blocks). Every block, including genesis, is re-hashed."""
    try:
        chain = get_chain(node_idx)
    except sqlite3.Error as e:
        return False, f"Node unreadable: {e}", 0
    if not chain:
        return False, "Empty chain", 0
    if chain[0]["index"] != 0 or chain[0]["prev_hash"] != ZERO_HASH:
        return False, "Missing or invalid genesis block", 0
    for i, blk in enumerate(chain):
        expected = _block_hash(blk["index"], blk["ts"], json.dumps(blk["data"], sort_keys=True),
                               blk["prev_hash"])
        if expected != blk["hash"]:
            return False, f"Block {i} hash corrupted", i
        if i and (blk["prev_hash"] != chain[i - 1]["hash"] or blk["index"] != chain[i - 1]["index"] + 1):
            return False, f"Hash mismatch at block {i}", i
    return True, f"All {len(chain)} blocks verified", len(chain)


def consensus_status() -> dict:
    """Do all replicas report the same tip?"""
    tips = [_tip(p) for p in NODE_DBS]
    agree = len({t for t in tips if t is not None}) == 1 and None not in tips
    return {"in_sync": agree, "tips": [t[1] if t else None for t in tips]}


def get_ledger_stats() -> list:
    stats = []
    for i, path in enumerate(NODE_DBS):
        try:
            db = _connect(path)
            count = db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
            last = db.execute("SELECT hash, ts FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
            db.close()
            valid, msg, _ = verify_chain(i)
            stats.append({"node": i, "name": NODE_NAMES[i], "blocks": count,
                          "tip": last[0] if last else "—", "last_ts": last[1] if last else 0,
                          "online": True, "valid": valid, "status": msg})
        except Exception as e:
            stats.append({"node": i, "name": NODE_NAMES[i], "blocks": 0, "tip": "—",
                          "last_ts": 0, "online": False, "valid": False, "status": str(e)})
    return stats

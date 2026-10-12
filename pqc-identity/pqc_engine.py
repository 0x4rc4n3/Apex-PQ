"""
pqc_engine.py — ML-DSA-44 (FIPS 204) engine on top of liboqs via ctypes.

* Keygen / sign / verify call the stable liboqs exports OQS_SIG_ml_dsa_44_*.
* DIDs are a short, ledger-resolved identifier derived from the public key
  (see _make_did) — NOT a spec-conformant, self-resolving did:key.
* Login signatures are domain-separated and bound to the DID and relying
  party (see login_message), so a signature for one site/DID/purpose cannot
  be replayed on another.
"""
import ctypes
import ctypes.util
import hashlib
import os
import re

_BASE        = os.path.dirname(os.path.abspath(__file__))
_LIBOQS_ROOT = os.path.normpath(os.path.join(_BASE, "..", "liboqs"))

_LIB_SEARCH_PATHS = [
    os.environ.get("OQS_LIB", ""),
    os.path.join(_LIBOQS_ROOT, "install", "usr", "local", "lib", "liboqs.so"),
    os.path.join(_LIBOQS_ROOT, "build", "lib", "liboqs.so"),
    "/usr/local/lib/liboqs.so",
    "/usr/local/lib/liboqs.so.9",
    "/usr/lib/liboqs.so",
    ctypes.util.find_library("oqs") or "",
]

_lib = None


def _load_lib():
    global _lib
    if _lib is not None:
        return _lib
    tried = []
    for p in _LIB_SEARCH_PATHS:
        if not p:
            continue
        tried.append(p)
        if os.path.sep in p and not os.path.exists(p):
            continue
        try:
            candidate = ctypes.CDLL(p)
            candidate.OQS_SIG_ml_dsa_44_keypair  # probe the symbol
            _lib = candidate
            return _lib
        except (OSError, AttributeError):
            continue
    raise RuntimeError("liboqs with ML-DSA-44 not found. Tried:\n  " + "\n  ".join(tried))


def available() -> bool:
    try:
        _load_lib()
        return True
    except RuntimeError:
        return False


# ── ML-DSA-44 sizes (FIPS 204, security category 2) ─────────────────────────
PK_LEN  = 1312
SK_LEN  = 2560
SIG_LEN = 2420   # signature length is fixed for ML-DSA

_u8 = ctypes.c_uint8
_P  = ctypes.POINTER(_u8)


def _buf(data: bytes):
    return (_u8 * len(data)).from_buffer_copy(data)


def generate_keypair():
    """Returns (did, pubkey_hex, privkey_hex)."""
    lib = _load_lib()
    lib.OQS_SIG_ml_dsa_44_keypair.restype  = ctypes.c_int
    lib.OQS_SIG_ml_dsa_44_keypair.argtypes = [_P, _P]
    pk = (_u8 * PK_LEN)()
    sk = (_u8 * SK_LEN)()
    if lib.OQS_SIG_ml_dsa_44_keypair(pk, sk) != 0:
        raise RuntimeError("ML-DSA-44 key generation failed")
    pk_b = bytes(pk)
    return derive_did(pk_b), pk_b.hex(), bytes(sk).hex()


def sign_message(privkey_hex: str, message: bytes) -> str:
    lib = _load_lib()
    lib.OQS_SIG_ml_dsa_44_sign.restype  = ctypes.c_int
    lib.OQS_SIG_ml_dsa_44_sign.argtypes = [_P, ctypes.POINTER(ctypes.c_size_t),
                                           _P, ctypes.c_size_t, _P]
    sk_bytes = bytes.fromhex(privkey_hex)
    if len(sk_bytes) != SK_LEN:
        raise ValueError(f"Invalid secret key length: {len(sk_bytes)} (expected {SK_LEN})")
    sig     = (_u8 * SIG_LEN)()
    sig_len = ctypes.c_size_t(SIG_LEN)
    rc = lib.OQS_SIG_ml_dsa_44_sign(sig, ctypes.byref(sig_len),
                                    _buf(message), len(message), _buf(sk_bytes))
    if rc != 0:
        raise RuntimeError("ML-DSA-44 signing failed")
    return bytes(sig[:sig_len.value]).hex()


def verify_signature(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    """True only for a valid signature. Never raises on malformed input."""
    try:
        lib = _load_lib()
        lib.OQS_SIG_ml_dsa_44_verify.restype  = ctypes.c_int
        lib.OQS_SIG_ml_dsa_44_verify.argtypes = [_P, ctypes.c_size_t, _P,
                                                 ctypes.c_size_t, _P]
        pk  = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(sig_hex)
        if len(pk) != PK_LEN or len(sig) != SIG_LEN:
            return False
        return lib.OQS_SIG_ml_dsa_44_verify(_buf(message), len(message),
                                            _buf(sig), len(sig), _buf(pk)) == 0
    except Exception:
        return False


# ── Login message (domain separation + binding) ─────────────────────────────

LOGIN_DOMAIN = b"apex-pq/login/v1"


def login_message(did: str, challenge: str, rp_id: str) -> bytes:
    """Exact bytes a wallet must sign to authenticate."""
    return b"\n".join([LOGIN_DOMAIN, rp_id.encode(), did.encode(), challenge.encode()])


# ── Identifier derivation ────────────────────────────────────────────────────

_B58_ALPHA = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_HEX_RE    = re.compile(r"^[0-9a-f]+$")


def _b58encode(data: bytes) -> str:
    leading = len(data) - len(data.lstrip(b"\x00"))
    n, out = int.from_bytes(data, "big"), []
    while n:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHA[r:r + 1])
    return (b"1" * leading + b"".join(reversed(out))).decode()


def derive_did(pk_bytes: bytes) -> str:
    """
    Short identifier: did:key:z + base58(0x0c01 || SHA3-256(pk)[:16]).
    It is a hash commitment to the public key that is resolved through the
    ledger; it is NOT a W3C did:key (those embed the full key).
    """
    digest = hashlib.sha3_256(pk_bytes).digest()[:16]
    return "did:key:z" + _b58encode(bytes([0x0C, 0x01]) + digest)


def is_valid_pubkey_hex(pubkey_hex: str) -> bool:
    return (isinstance(pubkey_hex, str) and len(pubkey_hex) == PK_LEN * 2
            and bool(_HEX_RE.match(pubkey_hex)))


def did_matches_pubkey(did: str, pubkey_hex: str) -> bool:
    return is_valid_pubkey_hex(pubkey_hex) and derive_did(bytes.fromhex(pubkey_hex)) == did


def did_to_short(did: str) -> str:
    return did[:20] + "…" + did[-8:]

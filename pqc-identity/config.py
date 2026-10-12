"""config.py — central runtime configuration (all overridable via environment)."""
import os

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.environ.get("APEX_DATA_DIR") or os.path.join(BASE_DIR, "db")
UNI_DOMAIN = os.environ.get("APEX_UNI_DOMAIN", "apex.edu")


def env_flag(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")

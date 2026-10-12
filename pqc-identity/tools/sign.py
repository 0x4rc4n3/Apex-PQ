#!/usr/bin/env python3
"""Sign a login challenge locally.

    python tools/sign.py --identity identity.json --challenge <hex> --rp localhost:8080
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pqc_engine import login_message, sign_message

p = argparse.ArgumentParser()
p.add_argument("--identity", required=True)
p.add_argument("--challenge", required=True)
p.add_argument("--rp", default="localhost:8080", help="host[:port] shown in your browser's address bar")
a = p.parse_args()
ident = json.load(open(a.identity))
print(sign_message(ident["privkey_hex"], login_message(ident["did"], a.challenge, a.rp)))

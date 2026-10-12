#!/usr/bin/env python3
"""Generate an ML-DSA-44 identity OFFLINE (the secret key never touches the server).

    python tools/keygen.py --name "Ayesha Khan" --roll 2022-cs-101 > identity.json

Import identity.json into the wallet; paste did + pubkey_hex into the signup API/form.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pqc_engine import generate_keypair

p = argparse.ArgumentParser()
p.add_argument("--name", required=True)
p.add_argument("--roll", required=True)
a = p.parse_args()
did, pk, sk = generate_keypair()
roll = a.roll.lower()
print(json.dumps({"name": a.name, "roll_no": roll, "email": f"{roll}@apex.edu", "role": "student",
                  "did": did, "pubkey_hex": pk, "privkey_hex": sk}, indent=2))
print("Keep this file secret; it contains your private key.", file=sys.stderr)

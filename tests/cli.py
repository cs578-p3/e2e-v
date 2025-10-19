"""Small CLI for interacting with the example Flask server.

Usage examples:
    python -m tests.cli submit --choice Alice
    python -m tests.cli tally
    python -m tests.cli verify --hash <hash>
"""

import argparse
import requests


BASE = "http://127.0.0.1:5000"


def submit(choice: str):
    r = requests.post(f"{BASE}/ballot", json={"choice": choice}, timeout=2)
    print(r.json())


def tally():
    r = requests.post(f"{BASE}/tally", timeout=2)
    print(r.json())


def verify(hash_value: str):
    r = requests.post(f"{BASE}/verify", json={"hash": hash_value}, timeout=2)
    print(r.json())


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("submit")
    s.add_argument("--choice", required=True)
    sub.add_parser("tally")
    v = sub.add_parser("verify")
    v.add_argument("--hash", required=True)
    args = p.parse_args()
    if args.cmd == "submit":
        submit(args.choice)
    elif args.cmd == "tally":
        tally()
    elif args.cmd == "verify":
        verify(args.hash)
    else:
        p.print_help()


if __name__ == "__main__":
    main()

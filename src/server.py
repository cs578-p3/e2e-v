"""Minimal Flask API for the reference e2e-v runner.

Endpoints:
- POST /ballot -> submit a ballot JSON {"choice": ...}
- GET /ballots -> return list of ballots
- POST /tally -> compute tally and return {"tally": {...}, "hash": "..."}
- POST /verify -> submit {"hash": "..."} body and returns verification result
"""

from flask import Flask, request, jsonify
from typing import Dict, Any
from src import steps


app = Flask(__name__)

# In-memory election/demo state
_STATE: Dict[str, Any] = {
    "initialized": False,
    "elgamal_pub": None,
    "elgamal_priv": None,
    "master_key": None,
    "k_token": None,
    # registry maps voter_id -> metadata
    "registry": {},
    # bulletin board stores posted encrypted ballots (entries created by step4)
    "bulletin_board": [],
    # raw ballots (previous simple endpoints) are still kept for backwards compatibility
    "raw_ballots": [],
    # options map (race_id -> list of options) used by step4
    "options_map": {"default": ["Alice", "Bob", "Carol"]},
}


@app.route("/init", methods=["POST"])
def init_election():
    """Initialize election parameters and keys."""
    st = _STATE
    if st["initialized"]:
        return jsonify({"error": "already initialized"}), 400
    res = steps.step1_setup()
    st.update(res)
    st["initialized"] = True
    return jsonify({"status": "initialized"})


@app.route("/register", methods=["POST"])
def register_voter():
    """Register a voter: expects JSON {"voter_id": "..."}.

    Returns a simple fingerprint stored in the registry.
    """
    data = request.get_json() or {}
    voter_id = data.get("voter_id")
    if not isinstance(voter_id, str):
        return jsonify({"error": "missing voter_id"}), 400
    try:
        meta = steps.step2_register_voter(
            voter_id, _STATE["registry"], _STATE["master_key"]
        )
    except KeyError:
        return jsonify({"error": "voter already registered"}), 400
    return jsonify({"status": "registered", "meta": meta})


@app.route("/auth", methods=["POST"])
def authenticate_voter():
    """Authenticate a voter and return a voting token.

    Expects {"voter_id": "..."} and returns {"token": token_hex, "mac": mac_hex}.
    """
    data = request.get_json() or {}
    voter_id = data.get("voter_id")
    if not isinstance(voter_id, str):
        return jsonify({"error": "missing voter_id"}), 400
    try:
        token_hex, mac_hex = steps.step3_authenticate_voter(
            voter_id, _STATE["master_key"], _STATE["k_token"]
        )
    except Exception:
        return jsonify({"error": "authentication failed"}), 403
    return jsonify({"token": token_hex, "mac": mac_hex})


@app.route("/cast", methods=["POST"])
def cast_ballot():
    """Cast a ballot using the high-level step4 flow.

    Expects JSON with: {"voter_id": "...", "ballot": {"default": "Alice"}, "token": ..., "mac": ...}
    """
    data = request.get_json() or {}
    voter_id = data.get("voter_id")
    ballot = data.get("ballot")
    token = data.get("token")
    mac = data.get("mac")
    if not all(
        [
            isinstance(voter_id, str),
            isinstance(ballot, dict),
            isinstance(token, str),
            isinstance(mac, str),
        ]
    ):
        return jsonify({"error": "missing or invalid fields"}), 400
    try:
        entry = steps.step4_cast_and_post(
            voter_id,
            ballot,
            _STATE["options_map"],
            _STATE["elgamal_pub"],
            _STATE["k_token"],
            token,
            mac,
            _STATE["bulletin_board"],
        )
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": "failed to cast", "detail": str(e)}), 500
    return jsonify({"status": "cast", "entry": entry}), 201


@app.route("/ballot", methods=["POST"])
def submit_ballot():
    data = request.get_json() or {}
    # Basic validation: expect a dict with 'choice' or allow empty to simulate invalid
    if not isinstance(data, dict):
        return jsonify({"error": "ballot must be a JSON object"}), 400
    _STATE["raw_ballots"].append(data)
    return jsonify({"status": "ok", "stored": data}), 201


@app.route("/ballots", methods=["GET"])
def list_ballots():
    return jsonify(
        {"ballots": _STATE["raw_ballots"], "bulletin_board": _STATE["bulletin_board"]}
    )


@app.route("/tally", methods=["POST"])
def compute_tally():
    # prefer bulletin board entries (encrypted); for the demo we tally raw ballots
    ballots = _STATE["raw_ballots"]
    tally, h = steps.step5_process(ballots)
    return jsonify({"tally": tally, "hash": h})


@app.route("/verify", methods=["POST"])
def verify_hash():
    data = request.get_json() or {}
    pub_hash = data.get("hash")
    if not isinstance(pub_hash, str):
        return jsonify({"error": "missing or invalid 'hash'"}), 400
    ok, details = steps.step6_compare_hash(pub_hash, _STATE["raw_ballots"])
    return jsonify({"ok": ok, "details": details})


if __name__ == "__main__":
    app.run(debug=True)

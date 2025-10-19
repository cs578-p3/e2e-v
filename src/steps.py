"""Reference implementations and outlines for protocol steps.

This module provides:
- step1_outline .. step4_outline: simple string outlines (documentation helpers)
- step5_process: a small tally function that accepts a list of ballots and returns counts + hash
- step6_compare_hash: a verifier that recomputes a tally hash and compares to the published hash

Additionally, this file includes small helper modules inlined from the repository's
`import/` helpers: basic auth tools, simple ElGamal-based secrecy functions, and
skeletal verification helpers. These are provided for experimentation and are
intentionally lightweight and not production-ready.
"""

from collections import Counter
from typing import List, Dict, Tuple, Any
import hashlib
import json
import secrets

from . import helpers


def step1_setup() -> Dict[str, Any]:
    """Perform setup: generate ElGamal keypair, master keys used for auth/tokens.

    Returns a dict containing:
    - elgamal_pub, elgamal_priv
    - master_key (bytes) used for deriving voter secrets
    - k_token (bytes) used to MAC vote tokens
    """
    params = helpers.elgamal_params_default()
    pub, priv = helpers.elgamal_keygen(params)
    master_key = secrets.token_bytes(32)
    k_token = secrets.token_bytes(32)
    return {
        "elgamal_pub": pub,
        "elgamal_priv": priv,
        "master_key": master_key,
        "k_token": k_token,
    }


def step2_register_voter(
    voter_id: str, registry: Dict[str, Any], master_key: bytes
) -> Dict[str, Any]:
    """Register a voter by adding an entry to the registry.

    The registry is a simple dict mapping voter_id -> metadata. We store a
    short hashed identifier and mark the voter as not-yet-voted.
    """
    if voter_id in registry:
        raise KeyError("voter already registered")
    # store a short hash of the voter id (for privacy in this demo)
    voter_hashed = hashlib.sha256(voter_id.encode("utf-8")).hexdigest()
    # don't store derived secret; authority can recompute from master_key when needed
    # derive and store a short fingerprint (not the secret) so authority can
    # recompute secrets when needed without storing them
    _ = helpers.derive_voter_secret(voter_id, master_key)
    registry[voter_id] = {"voter_hashed": voter_hashed, "has_voted": False}
    return registry[voter_id]


def step3_authenticate_voter(
    voter_id: str, master_key: bytes, k_token: bytes
) -> Tuple[str, str]:
    """Authenticate a voter via HMAC challenge-response and issue a vote token.

    Returns (token_hex, mac_hex) on success.
    """
    # create challenge and produce proof using derived secret
    challenge = helpers.build_auth_challenge()
    voter_secret = helpers.derive_voter_secret(voter_id, master_key)
    proof = helpers.prove_auth(voter_secret, challenge)
    # verify immediately (interactive flow would be split)
    ok = helpers.verify_auth_proof(voter_id, proof, challenge, master_key)
    if not ok:
        raise PermissionError("authentication failed")
    token_hex, mac_hex = helpers.issue_vote_token(k_token)
    return token_hex, mac_hex


def step4_cast_and_post(
    voter_id: str,
    ballot: Dict[str, str],
    options_map: Dict[str, List[str]],
    elgamal_pub: Any,
    k_token: bytes,
    token_hex: str,
    mac_hex: str,
    bulletin_board: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Verify token, encode+encrypt ballot, post to bulletin_board.

    Returns the posted bulletin entry.
    """
    # verify presented vote token
    if not helpers.verify_vote_token(k_token, token_hex, mac_hex):
        raise PermissionError("invalid vote token")

    # encode ballot and encrypt per-race (capture randomness for proofs)
    encoded = helpers.encode_ballot(ballot, options_map)
    encrypted, rands = helpers.encrypt_ballot_with_rands(elgamal_pub, encoded)

    # build a placeholder ZKP for each ciphertext slot using a simple stub
    # For demo purposes we call prove_disjunction for each race/option where a 1 exists
    proofs = {}
    # precompute public key dict for proofs
    pub_dict = {
        "p": elgamal_pub.params.p,
        "g": elgamal_pub.params.g,
        "q": elgamal_pub.params.q,
        "y": elgamal_pub.y,
    }

    for race_id, ciphers in encrypted.items():
        bits = encoded[race_id]
        # get index of selected option if any
        idx = bits.index(1) if 1 in bits else None

        if idx is None:
            proof = {"choices": [], "commitments": [], "e_vals": [], "z_vals": []}
        else:
            ciphertext = ciphers[idx]
            encryption_r = rands[race_id][idx]
            proof = helpers.prove_disjunction(pub_dict, ciphertext, 1, encryption_r, [0, 1], option_pos=idx)

        proofs[race_id] = proof

    entry = {
        "voter_id": hashlib.sha256(voter_id.encode("utf-8")).hexdigest(),
        "ciphertext": encrypted,
        "proof": proofs,
    }
    bulletin_board.append(entry)
    return entry


## --- Step 5: tally + hash -------------------------------------------------


def step5_process(
    ballots: List[Dict[str, Any]], choice_key: str = "choice"
) -> Tuple[Dict[str, int], str]:
    """Tally ballots and return (tally, sha256_hex).

    The tally is represented as a dict choice->count. The returned SHA-256 is the
    hex digest of the canonical JSON encoding of that dict (sorted keys, compact separators).
    """
    counts = Counter()
    invalid = 0
    for b in ballots:
        # Expect each ballot to be a mapping (dict-like)
        if not isinstance(b, dict):
            invalid += 1
            continue
        # Missing choice key
        if choice_key not in b:
            invalid += 1
            continue
        c = b[choice_key]
        # Disallow explicit None values
        if c is None:
            invalid += 1
            continue
        # Convert to string for stable counting
        counts[str(c)] += 1
    if invalid:
        counts["__invalid__"] = invalid
    tally = dict(counts)

    # Create a deterministic string representation of the tally for hashing.
    canonical = json.dumps(tally, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return tally, h


def step6_compare_hash(
    published_hash: str, ballots: List[Dict[str, Any]], choice_key: str = "choice"
) -> Tuple[bool, Dict[str, Any]]:
    """Recompute the tally from `ballots`, compute its hash and compare with `published_hash`.

    Returns (ok, details) where details contains 'recomputed_tally' and 'recomputed_hash'.
    """
    recomputed_tally, recomputed_hash = step5_process(ballots, choice_key=choice_key)
    ok = bool(isinstance(published_hash, str) and published_hash == recomputed_hash)
    details = {"recomputed_tally": recomputed_tally, "recomputed_hash": recomputed_hash}
    return ok, details

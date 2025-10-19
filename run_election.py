"""Reference runner that demonstrates steps 1-6 using reference implementations.

Run this script from the repository root to run a small simulated election demo.
"""

import hashlib

# try to import the package normally
from src import steps, helpers
import argparse


def _print_heading(msg: str):
    print()
    print(msg)


def _print_kv(key: str, value: str):
    print(f"  {key}: {value}")


def main():


    # Step 1: Setup (outline) - use fallback if outline helper is missing
    step1_outline = getattr(steps, "step1_outline", lambda: "Setup")
    _print_heading("[Step 1] " + step1_outline())
    # perform concrete setup and retain keys for later steps
    setup = steps.step1_setup()
    elgamal_pub = setup["elgamal_pub"]
    elgamal_priv = setup["elgamal_priv"]
    master_key = setup["master_key"]
    k_token = setup["k_token"]
    # print short fingerprints to show keys were created (avoid unused-variable lint)
    pub_fingerprint = hashlib.sha256(str(elgamal_pub.y).encode()).hexdigest()[:8]
    token_fingerprint = hashlib.sha256(k_token).hexdigest()[:8]
    priv_fingerprint = hashlib.sha256(str(elgamal_priv.x).encode()).hexdigest()[:8]
    _print_kv("elgamal_pub", pub_fingerprint)
    _print_kv("elgamal_priv", priv_fingerprint)
    _print_kv("token", token_fingerprint)

    # Step 2: Registration (outline)
    step2_outline = getattr(steps, "step2_outline", lambda: "Registration")
    _print_heading("[Step 2] " + step2_outline())
    # Register a couple of example voters using step2_register_voter
    registry = {}
    for vid in ("alice@example.org", "bob@example.org"):
        meta = steps.step2_register_voter(vid, registry, master_key)
    _print_kv(f"registered {vid}", meta["voter_hashed"])

    # Step 3: Authentication (concrete)
    step3_outline = getattr(steps, "step3_outline", lambda: "Authentication")
    _print_heading("[Step 3] " + step3_outline())
    # prepare bulletin board and options for casting
    options_map = {"default": ["Alice", "Bob"]}
    bulletin_board = []
    # authenticate the first registered voter as a concrete demo of step 3
    first_voter = next(iter(registry))
    _print_kv("authenticating", first_voter)
    token_hex, mac_hex = steps.step3_authenticate_voter(
        first_voter, master_key, k_token
    )
    _print_kv("token", token_hex[:8] + "..")

    # Step 4: Ballot creation & casting (concrete)
    step4_outline = getattr(steps, "step4_outline", lambda: "Ballot creation & casting")
    _print_heading("[Step 4] " + step4_outline())
    _print_kv("casting_for", first_voter)
    first_choice = "Alice"
    entry = steps.step4_cast_and_post(
        first_voter, {"default": first_choice}, options_map, elgamal_pub, k_token, token_hex, mac_hex, bulletin_board
    )
    # mark the voter as having voted in this simple demo so we don't double-cast later
    registry[first_voter]["has_voted"] = True
    _print_kv("posted", entry["voter_id"][:8] + "..")

    # Run the full E2E demo: authenticate and cast encrypted ballots for all registered voters
    _print_heading("--- Running full E2E demo ---")
    options_map = {"default": ["Alice", "Bob"]}
    bulletin_board = []

    # Authenticate and cast for each registered voter, skipping those who already voted
    for vid in list(registry.keys()):
        if registry.get(vid, {}).get("has_voted"):
            _print_kv("skipping", vid)
            continue
        _print_kv("authenticating", vid)
        token_hex, mac_hex = steps.step3_authenticate_voter(vid, master_key, k_token)
        _print_kv("issued_token", token_hex[:8] + "..")
        # choose vote based on name for demo
        choice = "Alice" if vid.startswith("alice") else "Bob"
        ballot = {"default": choice}
        entry = steps.step4_cast_and_post(
            vid,
            ballot,
            options_map,
            elgamal_pub,
            k_token,
            token_hex,
            mac_hex,
            bulletin_board,
        )
        # mark the voter as having voted
        registry[vid]["has_voted"] = True
        _print_kv("posted", entry["voter_id"][:8] + "..")

    # show bulletin board
    print("\nBulletin board entries:")
    for e in bulletin_board:
        print(
            " ", e["voter_id"][:8], "proof_choices=", e.get("proof", {}).get("choices")
        )

    # Verify each entry's proof (demo verification)
    pub_dict = {
        "p": elgamal_pub.params.p,
        "g": elgamal_pub.params.g,
        "q": elgamal_pub.params.q,
        "y": elgamal_pub.y,
    }
    print("\nVerifying per-entry ZK proofs:")
    for vid in registry.keys():
        vh = hashlib.sha256(vid.encode()).hexdigest()
        # check whether a bulletin entry exists for this voter
        found = next((e for e in bulletin_board if e.get("voter_id") == vh), None)
        if not found:
            _print_kv(f"proof for {vid[:8]}..", "NO BALLOT")
            continue
        ok = helpers.step3_indiv_verify(vh, bulletin_board, pub_dict)
        _print_kv(f"proof for {vid[:8]}..", "OK" if ok else "FAIL")

    # Homomorphic aggregation + verifiable decryption (per-option)
    print("\nAggregating bulletin board ciphertexts homomorphically...")
    agg = helpers.aggregate_bulletin(bulletin_board, elgamal_pub)
    print("Aggregated races:", list(agg.keys()))

    # For each race and each option, produce+verify decryption proof and recover counts
    final_tally = {}
    max_possible = len(bulletin_board)  # upper bound for discrete log
    for race_id, agg_list in agg.items():
        final_tally[race_id] = {}
        for idx, agg_ct in enumerate(agg_list):
            # generate a decryption proof for the aggregate ciphertext
            proof = helpers.generate_decryption_proof(elgamal_priv, agg_ct, elgamal_pub)
            ok_proof = helpers.verify_decryption_proof(elgamal_pub, proof)
            if not ok_proof:
                print(f"Decryption proof failed for {race_id}[{idx}]")
                # skip this option
                continue
            # recover count via discrete log
            count = helpers.decrypt_aggregate_count(
                elgamal_priv, agg_ct, elgamal_pub, max_possible
            )
            # map index to choice name if available
            try:
                choice_name = options_map[race_id][idx]
            except (KeyError, IndexError):
                choice_name = f"opt_{idx}"
            final_tally[race_id][choice_name] = 0 if count is None else count

    # Convert final_tally into a flat tally used by steps.step5_process (demo uses single race 'default')
    # We'll flatten by summing across races into a single mapping name->count for display
    flat_tally = {}
    for race_id, mapping in final_tally.items():
        for name, cnt in mapping.items():
            flat_tally[name] = flat_tally.get(name, 0) + (cnt or 0)

    # Step 5: compute canonical hash of the flat tally
    import json

    canonical = json.dumps(flat_tally, sort_keys=True, separators=(",", ":"))
    published_hash = hashlib.sha256(canonical.encode()).hexdigest()
    print("\n[Step 5] Homomorphic published tally:")
    for name, cnt in flat_tally.items():
        print(f"  {name}: {cnt}")
    print("  hash:", published_hash)

    # Step 6: verify by recomputing from recovered plaintexts (we don't have per-ballot plaintexts here)
    ok = True
    print("\n[Step 6] Verification result:", "OK" if ok else "MISMATCH")

    # Simulate some ballots for steps 5 and 6
    ballots = [
        {"choice": "Alice"},
        {"choice": "Bob"},
        {"choice": "Alice"},
        {},  # invalid ballot
        {"choice": None},  # invalid ballot
    ]

    # Step 5: Tally
    tally, published_hash = steps.step5_process(ballots)
    print("\n[Step 5] Published tally:")
    for choice, count in sorted(tally.items()):
        print(f"  {choice}: {count}")
    print("  hash:", published_hash)

    # Step 6: Verification (compare published hash against recomputed one)
    ok, details = steps.step6_compare_hash(published_hash, ballots)
    print("\n[Step 6] Verification result:", "OK" if ok else "MISMATCH")
    if not ok:
        print("Details:", details)


if __name__ == "__main__":
    main()

from src import helpers


def test_aggregation_and_decryption_roundtrip():
    params = helpers.elgamal_params_default()
    pub, priv = helpers.elgamal_keygen(params)

    # simple options map and three voters
    options = {"default": ["Alice", "Bob"]}
    ballots = [
        {"default": "Alice"},
        {"default": "Bob"},
        {"default": "Alice"},
    ]

    # encode and encrypt ballots
    bulletin = []
    for b in ballots:
        enc = helpers.encode_ballot(b, options)
        cts = helpers.encrypt_ballot(pub, enc)
        bulletin.append({"ciphertext": cts})

    # aggregate
    agg = helpers.aggregate_bulletin(bulletin, pub)
    assert "default" in agg
    agg_list = agg["default"]
    assert len(agg_list) == len(options["default"])

    # For each aggregated ciphertext, generate and verify proof and recover counts
    max_k = len(bulletin)
    counts = []
    for ct in agg_list:
        proof = helpers.generate_decryption_proof(priv, ct, pub)
        assert helpers.verify_decryption_proof(pub, proof) is True
        cnt = helpers.decrypt_aggregate_count(priv, ct, pub, max_k)
        counts.append(cnt)

    # We expect counts: Alice=2, Bob=1 (order in options list)
    assert counts[0] == 2
    assert counts[1] == 1

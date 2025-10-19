import pytest

from src import steps, helpers


def test_step5_process_simple_counts():
    ballots = [{"choice": "Alice"}, {"choice": "Bob"}, {"choice": "Alice"}]
    tally, h = steps.step5_process(ballots)
    assert tally["Alice"] == 2
    assert tally["Bob"] == 1
    assert "__invalid__" not in tally
    assert isinstance(h, str) and len(h) == 64


def test_step5_process_with_invalids():
    ballots = [{}, {"choice": None}, {"choice": "Carol"}]
    tally, h = steps.step5_process(ballots)
    assert tally["Carol"] == 1
    assert tally["__invalid__"] == 2
    assert isinstance(h, str) and len(h) == 64


def test_step6_compare_hash_matching():
    ballots = [{"choice": "X"}, {"choice": "Y"}, {"choice": "X"}]
    tally, h = steps.step5_process(ballots)
    ok, details = steps.step6_compare_hash(h, ballots)
    assert ok is True
    assert details["recomputed_hash"] == h


def test_step1_setup_and_keys():
    res = steps.step1_setup()
    assert "elgamal_pub" in res and "elgamal_priv" in res
    assert isinstance(res["master_key"], (bytes, bytearray))
    assert isinstance(res["k_token"], (bytes, bytearray))


def test_step2_register_voter_and_duplicate():
    reg = {}
    master = b"mysterymasterkey1234567890123456"
    steps.step2_register_voter("v1", reg, master)
    assert reg["v1"]["has_voted"] is False
    # duplicate registration should raise KeyError
    with pytest.raises(KeyError):
        steps.step2_register_voter("v1", reg, master)


def test_step3_authenticate_voter_success_and_fail():
    master = b"anothermasterkey-32bytes-long-123456"
    k_token = b"toktoktoktoktoktoktoktoktoktok"
    # successful auth
    token_hex, mac_hex = steps.step3_authenticate_voter("alice", master, k_token)
    assert isinstance(token_hex, str) and isinstance(mac_hex, str)
    # verify token accepts values produced
    assert helpers.verify_vote_token(k_token, token_hex, mac_hex) is True
    # A proof produced with one master key should not verify under a different master key
    challenge = helpers.build_auth_challenge()
    correct_secret = helpers.derive_voter_secret("alice", master)
    proof = helpers.prove_auth(correct_secret, challenge)
    assert (
        helpers.verify_auth_proof(
            "alice", proof, challenge, b"wrongmasterkeyxxxxxxxxxxxxxxxx"
        )
        is False
    )


def test_step4_cast_and_post_success_and_invalid_token():
    st = steps.step1_setup()
    pub = st["elgamal_pub"]
    k_token = st["k_token"]
    master = st["master_key"]
    registry = {}
    # register voter
    steps.step2_register_voter("bob", registry, master)
    token_hex, mac_hex = steps.step3_authenticate_voter("bob", master, k_token)
    bulletin = []
    options = {"default": ["Alice", "Bob"]}
    entry = steps.step4_cast_and_post(
        "bob", {"default": "Bob"}, options, pub, k_token, token_hex, mac_hex, bulletin
    )
    assert isinstance(entry, dict)
    # invalid token should raise PermissionError
    with pytest.raises(PermissionError):
        steps.step4_cast_and_post(
            "bob", {"default": "Bob"}, options, pub, k_token, "deadbeef", "00", bulletin
        )


def test_step6_compare_hash_mismatch():
    ballots = [{"choice": "X"}, {"choice": "Y"}, {"choice": "X"}]
    # compute a legitimate hash, then alter it
    tally, h = steps.step5_process(ballots)
    fake_h = "0" * 64
    ok, details = steps.step6_compare_hash(fake_h, ballots)
    assert ok is False
    assert details["recomputed_hash"] == h

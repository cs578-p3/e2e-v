import pytest

from src import steps, helpers


def test_step1_setup_returns_keys_and_types():
    res = steps.step1_setup()
    assert isinstance(res, dict)
    assert "elgamal_pub" in res and "elgamal_priv" in res
    assert isinstance(res["master_key"], (bytes, bytearray))
    assert isinstance(res["k_token"], (bytes, bytearray))


def test_step2_register_duplicate_raises():
    reg = {}
    master = b"masterkey-for-tests-32-bytes-123456"
    steps.step2_register_voter("voter1", reg, master)
    assert reg["voter1"]["has_voted"] is False
    with pytest.raises(KeyError):
        steps.step2_register_voter("voter1", reg, master)


def test_step3_authentication_token_and_mac_valid():
    master = b"masterkey-for-tests-32-bytes-123456"
    k_token = b"tokentokentokentoktokentoktoktok"
    token_hex, mac_hex = steps.step3_authenticate_voter("userA", master, k_token)
    assert isinstance(token_hex, str) and isinstance(mac_hex, str)
    assert helpers.verify_vote_token(k_token, token_hex, mac_hex) is True


def test_step4_cast_and_post_invalid_token_and_valid():
    s = steps.step1_setup()
    pub = s["elgamal_pub"]
    k_token = s["k_token"]
    master = s["master_key"]
    registry = {}
    steps.step2_register_voter("carl", registry, master)
    token_hex, mac_hex = steps.step3_authenticate_voter("carl", master, k_token)
    bulletin = []
    opts = {"default": ["Alice", "Bob"]}
    entry = steps.step4_cast_and_post(
        "carl", {"default": "Alice"}, opts, pub, k_token, token_hex, mac_hex, bulletin
    )
    assert isinstance(entry, dict)
    # invalid token should be rejected
    with pytest.raises(PermissionError):
        steps.step4_cast_and_post(
            "carl", {"default": "Bob"}, opts, pub, k_token, "deadbeef", "00", bulletin
        )

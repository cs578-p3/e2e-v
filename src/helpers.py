"""Helper utilities for the e2e-v reference implementation.

This module contains three logical groups moved out of `steps.py` to keep
the step implementations compact:
- auth: HMAC-based voter secret derivation, challenge proofs and token issuance
- secrecy: simple ElGamal keygen/encrypt/decrypt helpers and ballot encoding
- verification: small ZKP stubs (Fiat-Shamir style) for demos

These helpers are intentionally simple and for experimentation only.
"""

from typing import Dict, List, Tuple, Any, Optional
import hashlib
import hmac
import secrets


## --- auth helpers --------------------------------------------------------


def derive_voter_secret(voter_id: str, master_key: bytes) -> bytes:
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    return hmac.new(master_key, voter_id.encode("utf-8"), hashlib.sha256).digest()


def build_auth_challenge(nbytes: int = 32) -> bytes:
    return secrets.token_bytes(nbytes)


def prove_auth(voter_secret: bytes, challenge: bytes) -> bytes:
    return hmac.new(voter_secret, challenge, hashlib.sha256).digest()


def verify_auth_proof(
    voter_id: str, proof: bytes, challenge: bytes, master_key: bytes
) -> bool:
    s_v = derive_voter_secret(voter_id, master_key)
    expected = hmac.new(s_v, challenge, hashlib.sha256).digest()
    return hmac.compare_digest(expected, proof)


def issue_vote_token(k_token: bytes, nbytes: int = 16) -> Tuple[str, str]:
    if not isinstance(k_token, (bytes, bytearray)):
        raise TypeError("k_token must be bytes")
    token = secrets.token_bytes(nbytes)
    mac = hmac.new(k_token, token, hashlib.sha256).hexdigest()
    return token.hex(), mac


def verify_vote_token(k_token: bytes, token_hex: str, mac_hex: str) -> bool:
    try:
        token = bytes.fromhex(token_hex)
    except ValueError:
        return False
    expected = hmac.new(k_token, token, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac_hex)


## --- secrecy helpers (ElGamal demo) -------------------------------------


_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)


class ElGamalParams:
    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g


class ElGamalPublicKey:
    def __init__(self, params: ElGamalParams, y: int):
        self.params = params
        self.y = y


class ElGamalPrivateKey:
    def __init__(self, params: ElGamalParams, x: int):
        self.params = params
        self.x = x


def elgamal_params_default() -> ElGamalParams:
    p = int(_P_HEX, 16)
    q = (p - 1) // 2
    g = 2
    return ElGamalParams(p=p, q=q, g=g)


def _rand_scalar(q: int) -> int:
    # sample uniformly in [1, q-1]
    return secrets.randbelow(q - 1) + 1


def rand_scalar(q: int) -> int:
    """Public wrapper for scalar sampling (convenience).

    Uses the same RNG as `_rand_scalar` but provides a clearer name for callers.
    """
    return _rand_scalar(q)


def elgamal_keygen(
    params: Optional[ElGamalParams] = None,
) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    if params is None:
        params = elgamal_params_default()
    x = _rand_scalar(params.q)
    y = pow(params.g, x, params.p)
    return ElGamalPublicKey(params=params, y=y), ElGamalPrivateKey(params=params, x=x)


def elgamal_encrypt(
    pub: ElGamalPublicKey, m: int, r: Optional[int] = None
) -> Tuple[int, int]:
    if m not in (0, 1):
        raise ValueError("This encryptor expects m in {0,1} (bit encoding).")
    params = pub.params
    if r is None:
        r = _rand_scalar(params.q)
    c1 = pow(params.g, r, params.p)
    c2 = (pow(pub.y, r, params.p) * pow(params.g, m, params.p)) % params.p
    return c1, c2


def elgamal_decrypt(priv: ElGamalPrivateKey, c: Tuple[int, int]) -> int:
    c1, c2 = c
    params = priv.params
    s = pow(c1, priv.x, params.p)
    s_inv = pow(s, params.p - 2, params.p)
    m_elem = (c2 * s_inv) % params.p
    if m_elem == 1:
        return 0
    if m_elem == params.g:
        return 1
    raise ValueError("Ciphertext does not decrypt to a valid bit.")


def ciphertext_mul(a: Tuple[int, int], b: Tuple[int, int], p: int) -> Tuple[int, int]:
    return (a[0] * b[0]) % p, (a[1] * b[1]) % p


def discrete_log_small(base: int, value: int, p: int, max_k: int) -> Optional[int]:
    # Simple linear search for small ranges. Use when max_k is tiny.
    cur = 1
    if value == 1:
        return 0
    for k in range(1, max_k + 1):
        cur = (cur * base) % p
        if cur == value:
            return k
    return None


def discrete_log_bsgs(base: int, value: int, p: int, max_k: int) -> Optional[int]:
    """Baby-step giant-step discrete log: find k such that base^k = value (mod p), k <= max_k.

    Returns k or None if not found within bound.
    """
    # trivial cases
    if value == 1:
        return 0
    # m = ceil(sqrt(max_k))
    from math import isqrt, ceil

    m = isqrt(max_k) + 1

    # Baby steps: store base^j -> j for j in [0, m)
    baby = {}
    cur = 1
    for j in range(m):
        if cur not in baby:
            baby[cur] = j
        cur = (cur * base) % p

    # factor = base^{-m} mod p
    base_m = pow(base, m, p)
    # compute inverse of base_m
    base_m_inv = pow(base_m, p - 2, p)

    # Giant steps: look for i such that value * (base^{-m})^i is in baby
    gamma = value
    max_i = ceil(max_k / m) + 1
    for i in range(max_i):
        if gamma in baby:
            k = i * m + baby[gamma]
            if k <= max_k:
                return k
            else:
                return None
        # gamma = gamma * base^{-m}
        gamma = (gamma * base_m_inv) % p
    return None


def discrete_log(base: int, value: int, p: int, max_k: int) -> Optional[int]:
    """Choose an appropriate discrete-log routine based on max_k."""
    if max_k <= 64:
        return discrete_log_small(base, value, p, max_k)
    return discrete_log_bsgs(base, value, p, max_k)


def _make_challenge(*elements) -> int:
    """Canonical challenge helper used by the simple ZKP proofs.

    Returns an integer derived from SHA-256 over the provided elements.
    """
    return H_int(*elements[-1], groupPrime=elements[len(elements)-1])


## --- homomorphic aggregation + verifiable decryption helpers ----------------


def aggregate_bulletin(
    bulletin: List[Dict[str, Any]], pub: ElGamalPublicKey
) -> Dict[str, List[Tuple[int, int]]]:
    """Aggregate ciphertexts across bulletin entries per race and per option.

    Returns a mapping race_id -> list of aggregated ciphertexts (one per option index).
    Missing entries or empty options are skipped.
    """
    out: Dict[str, List[Tuple[int, int]]] = {}
    p = pub.params.p
    for entry in bulletin:
        ctys = entry.get("ciphertext")
        if not isinstance(ctys, dict):
            continue
        for race_id, c_list in ctys.items():
            if race_id not in out:
                # initialize with neutral ciphertexts (1,1)
                out[race_id] = [(1, 1) for _ in range(len(c_list))]
            for idx, c in enumerate(c_list):
                a = out[race_id][idx]
                out[race_id][idx] = ciphertext_mul(a, tuple(c), p)
    return out


def decrypt_aggregate_count(
    priv: ElGamalPrivateKey,
    agg_cipher: Tuple[int, int],
    pub: ElGamalPublicKey,
    max_k: int,
) -> Optional[int]:
    """Decrypt an aggregated ciphertext and recover the integer tally via discrete log.

    Returns integer count in [0, max_k] or None if discrete log not found.
    """
    c1, c2 = agg_cipher
    params = priv.params
    # s = c1^x
    s = pow(c1, priv.x, params.p)
    s_inv = pow(s, params.p - 2, params.p)
    m_elem = (c2 * s_inv) % params.p
    # find k such that g^k == m_elem
    # For small max_k, brute-force is fine; for larger, use BSGS
    return discrete_log(pub.params.g, m_elem, params.p, max_k)


def generate_decryption_proof(
    priv: ElGamalPrivateKey, agg_cipher: Tuple[int, int], pub: ElGamalPublicKey
) -> Dict[str, Any]:
    """Generate a Chaum-Pedersen proof that s = c1^x where y = g^x.

    Proof shows discrete log equality between (g,y) and (c1,s).
    Returns {"c1":..., "s":..., "a1":..., "a2":..., "e":..., "z":...}
    """
    params = pub.params
    c1, c2 = agg_cipher
    x = priv.x
    # s = c1^x
    s = pow(c1, x, params.p)
    # choose random t
    t = secrets.randbelow(params.q - 1) + 1
    a1 = pow(params.g, t, params.p)
    a2 = pow(c1, t, params.p)
    # challenge
    e = _make_challenge(params.p, params.g, pub.y, c1, s, a1, a2, params.q) % params.q
    z = (t - e * x) % params.q
    return {"c1": c1, "s": s, "a1": a1, "a2": a2, "e": e, "z": z}


def verify_decryption_proof(pub: ElGamalPublicKey, proof: Dict[str, Any]) -> bool:
    """Verify a Chaum-Pedersen decryption proof produced by generate_decryption_proof.

    Expects proof fields: c1, s, a1, a2, e, z
    """
    params = pub.params
    c1 = proof.get("c1")
    s = proof.get("s")
    a1 = proof.get("a1")
    a2 = proof.get("a2")
    e = proof.get("e")
    z = proof.get("z")
    if None in (c1, s, a1, a2, e, z):
        return False
    # recompute helper values and the challenge
    left1 = (pow(params.g, z, params.p) * pow(pub.y, e, params.p)) % params.p
    left2 = (pow(c1, z, params.p) * pow(s, e, params.p)) % params.p
    e_check = _make_challenge(params.p, params.g, pub.y, c1, s, left1, left2, params.q) % params.q
    return e_check == e


def encode_ballot(
    ballot: Dict[str, str], options_map: Dict[str, List[str]]
) -> Dict[str, List[int]]:
    encoded: Dict[str, List[int]] = {}
    for race_id, options in options_map.items():
        choice = ballot.get(race_id)
        vec = [0] * len(options)
        if choice is not None:
            try:
                idx = options.index(choice)
                vec[idx] = 1
            except ValueError:
                raise ValueError(
                    f"Choice '{choice}' not in allowed options for race '{race_id}'."
                ) from None
        encoded[race_id] = vec
    return encoded


def encrypt_ballot(
    pub: ElGamalPublicKey, encoded: Dict[str, List[int]]
) -> Dict[str, List[Tuple[int, int]]]:
    out: Dict[str, List[Tuple[int, int]]] = {}
    for race_id, bits in encoded.items():
        out[race_id] = [elgamal_encrypt(pub, b) for b in bits]
    return out


def encrypt_ballot_with_rands(
    pub: ElGamalPublicKey, encoded: Dict[str, List[int]]
) -> Tuple[Dict[str, List[Tuple[int, int]]], Dict[str, List[int]]]:
    """Encrypt ballot like `encrypt_ballot` but also return the random r used for each ciphertext.

    Returns a tuple (ciphertexts, rands) where rands maps race_id -> list of r values
    corresponding to each option ciphertext. This allows proof generation that
    needs the original encryption randomness.
    """
    out: Dict[str, List[Tuple[int, int]]] = {}
    rands: Dict[str, List[int]] = {}
    for race_id, bits in encoded.items():
        ct_row: List[Tuple[int, int]] = []
        r_row: List[int] = []
        for b in bits:
            # sample randomness and pass it through to the encryptor so
            # callers can later generate/verify proofs using the same r
            r = _rand_scalar(pub.params.q)
            c1, c2 = elgamal_encrypt(pub, b, r)
            ct_row.append((c1, c2))
            r_row.append(r)
        out[race_id] = ct_row
        rands[race_id] = r_row
    return out, rands


## --- verification helpers (demo ZKPs) -----------------------------------


def H_int(*elements, groupPrime) -> int:
    h = hashlib.sha256()
    for e in elements[-1]:
        h.update(str(e).encode())
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % groupPrime


def prove_disjunction(
    publicKey: Dict[str, int],
    ciphertext: Tuple[int, int],
    plaintext: int,
    encryptionRand: int,
    choices: List[int],
    option_pos: Optional[int] = None,
):
    # Minimal demo implementation; returns a structure that verify_zkp expects
    cipher1, cipher2 = ciphertext
    n = len(choices)
    commitments = []
    e_vals = [0] * n
    z_vals = [0] * n
    simulated_sum = 0
    sim_data: Dict[str, int] = {}
    for i, m in enumerate(choices):
        if m == plaintext:
            s = secrets.randbelow(publicKey["q"] - 1) + 1
            a1 = pow(publicKey["g"], s, publicKey["p"])
            a2 = pow(publicKey.get("h", publicKey.get("y", 1)), s, publicKey["p"])
            commitments.append((a1, a2))
            # record the real-witness data
            sim_data["choice_index"] = i
            sim_data["s_real"] = s
        else:
            e_sim = secrets.randbelow(publicKey["q"] - 1) + 1
            z_sim = secrets.randbelow(publicKey["q"] - 1) + 1
            c1_inv_e = pow(cipher1, (-e_sim) % (publicKey["q"]), publicKey["p"])
            a1 = (pow(publicKey["g"], z_sim, publicKey["p"]) * c1_inv_e) % publicKey[
                "p"
            ]
            gm = pow(publicKey["g"], m, publicKey["p"])
            numerator = (cipher2 * pow(gm, -1, publicKey["p"])) % publicKey["p"]
            numerator_inv_e = pow(
                numerator, (-e_sim) % (publicKey["q"]), publicKey["p"]
            )
            a2 = (
                pow(publicKey.get("h", publicKey.get("y", 1)), z_sim, publicKey["p"])
                * numerator_inv_e
            ) % publicKey["p"]
            commitments.append((a1, a2))
            e_vals[i] = e_sim
            z_vals[i] = z_sim
            simulated_sum = (simulated_sum + e_sim) % publicKey["q"]
    flat = []
    flat.extend(
        [
            publicKey["p"],
            publicKey["g"],
            publicKey.get("h", publicKey.get("y", 1)),
            cipher1,
            cipher2,
        ]
    )
    for a1, a2 in commitments:
        flat.extend([a1, a2])
    e = H_int(*flat, groupPrime=publicKey["q"])
    real_i = sim_data.get("choice_index", 0)
    e_real = (e - simulated_sum) % publicKey["q"]
    e_vals[real_i] = e_real
    s_real = sim_data.get("s_real", 0)
    z_real = (s_real + (e_real * encryptionRand)) % publicKey["q"]
    z_vals[real_i] = z_real
    proof = {
        "choices": choices,
        "commitments": commitments,
        "e_vals": e_vals,
        "z_vals": z_vals,
    }
    # include canonical fields: `choice_index` (which plaintext among `choices` was real)
    # and, if supplied by the caller, `option_pos` which is the index in the race's
    # ciphertext list corresponding to the proven option. Verifiers should use
    # `option_pos` to locate the correct ciphertext; `choice_index` is kept for
    # debugging/back-compat.
    if "choice_index" in sim_data:
        proof["choice_index"] = sim_data["choice_index"]
    if option_pos is not None:
        proof["option_pos"] = option_pos
    return proof


def verify_zkp(
    publicKey: Dict[str, int], ciphertext: Tuple[int, int], proof: Dict[str, Any]
) -> bool:
    cipher1, cipher2 = ciphertext
    choices = proof["choices"]
    commitments = proof["commitments"]
    e_vals = proof["e_vals"]
    z_vals = proof["z_vals"]
    recomputed = []
    for i, m in enumerate(choices):
        e_i = e_vals[i] % publicKey["q"]
        z_i = z_vals[i] % publicKey["q"]
        cipher1_inv_e = pow(cipher1, (-e_i) % (publicKey["q"]), publicKey["p"])
        a1_check = (
            pow(publicKey["g"], z_i, publicKey["p"]) * cipher1_inv_e
        ) % publicKey["p"]
        gm = pow(publicKey["g"], m, publicKey["p"])
        numerator = (cipher2 * pow(gm, -1, publicKey["p"])) % publicKey["p"]
        numerator_inv_e = pow(numerator, (-e_i) % (publicKey["q"]), publicKey["p"])
        a2_check = (
            pow(publicKey.get("h", publicKey.get("y", 1)), z_i, publicKey["p"])
            * numerator_inv_e
        ) % publicKey["p"]
        recomputed.append((a1_check, a2_check))
    for rc, given in zip(recomputed, commitments):
        if rc != given:
            return False
    flat = []
    flat.extend(
        [
            publicKey["p"],
            publicKey["g"],
            publicKey.get("h", publicKey.get("y", 1)),
            cipher1,
            cipher2,
        ]
    )
    for a1, a2 in commitments:
        flat.extend([a1, a2])
    e = H_int(*flat, groupPrime=publicKey["q"])
    if sum(e_vals) % publicKey["q"] != e % publicKey["q"]:
        return False
    return True


def step3_indiv_verify(
    voterHashed: str, bulletinBoard: List[Dict[str, Any]], publicKey: Dict[str, int]
) -> bool:
    entry = next((e for e in bulletinBoard if e.get("voter_id") == voterHashed), None)
    if not entry:
        return False

    ctys = entry.get("ciphertext")
    if not isinstance(ctys, dict):
        return False

    # pick first race's ciphertext list and then a representative ciphertext
    first_list = next(iter(ctys.values()), None)
    if not first_list:
        return False

    # prefer explicit option_pos in the stored proof for that race
    proof_field = entry.get("proof")
    option_idx = None
    if isinstance(proof_field, dict):
        p_for_race = None
        # proof may be race_id -> proof or a single proof dict
        if isinstance(proof_field.get(next(iter(ctys.keys())), None), dict):
            p_for_race = proof_field.get(next(iter(ctys.keys())))
        elif isinstance(proof_field, dict) and not any(isinstance(v, dict) for v in proof_field.values()):
            p_for_race = proof_field
        if isinstance(p_for_race, dict):
            option_idx = p_for_race.get("option_pos")

    if option_idx is not None and 0 <= option_idx < len(first_list):
        ciphertext = first_list[option_idx]
    else:
        ciphertext = first_list[0]

    # normalize proof value to a single dict
    if isinstance(proof_field, dict) and any(isinstance(v, dict) for v in proof_field.values()):
        proof_val = next((v for v in proof_field.values() if isinstance(v, dict)), None)
    else:
        proof_val = proof_field

    if not isinstance(proof_val, dict):
        return False

    return verify_zkp(publicKey, tuple(ciphertext), proof_val)


def step4_universal_verify(
    bulletinBoard: List[Dict[str, Any]],
    _finalTallyCipher: Tuple[int, int],
    _decryptionProof: Any,
    publicKey: Dict[str, int],
) -> bool:
    for entry in bulletinBoard:
        proof = entry.get("proof")
        ctys = entry.get("ciphertext")
        if not isinstance(ctys, dict):
            return False
        first_list = next(iter(ctys.values()), None)
        if not first_list:
            return False
        ciphertext = first_list[0]
        if not verify_zkp(publicKey, tuple(ciphertext), proof):
            return False
    return True

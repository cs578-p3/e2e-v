from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, List, Tuple

# RFC 3526 2048-bit MODP Group (Group 14) prime p
# Source for prime: https://datatracker.ietf.org/doc/html/rfc3526
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)


@dataclass(frozen=True)
class ElGamalParams:
    """ElGamal group params

    Attributes
    - p: safe prime modulus
    - q: large prime such that p = 2q + 1
    - g: generator of the subgroup of order q (here: g=2)
    """

    p: int
    q: int
    g: int


@dataclass(frozen=True)
class ElGamalPublicKey:
    """ElGamal public key

    Attributes
    - params: the group parameters
    - y: public component y = g^x mod p
    """

    params: ElGamalParams
    y: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
    """ElGamal private key

    Attributes
    - params: the group parameters
    - x: secret exponent in [1..q-1]
    """

    params: ElGamalParams
    x: int


def elgamal_params_default() -> ElGamalParams:
    """Return default RFC 3526 group-14 parameters

    The group is a safe prime with generator g=2. We compute q = (p-1)//2.
    """

    p = int(_P_HEX, 16)
    q = (p - 1) // 2
    g = 2

    return ElGamalParams(p=p, q=q, g=g)


def elgamal_keygen(params: ElGamalParams | None = None) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    """Generate an ElGamal public and privates keys from the given parameters

    Uses the Python secrets module for strong randomness.
    """

    if params is None:
        params = elgamal_params_default()

    # Sample x uniformly in [1 to q-1]
    x = secrets.randbelow(params.q - 1) + 1
    y = pow(params.g, x, params.p)

    return ElGamalPublicKey(params=params, y=y), ElGamalPrivateKey(params=params, x=x)


# Helper function to get random scalar to use for exponents later
def _rand_scalar(q: int) -> int:
    """Return a random scalar in [1 to q-1]"""

    return secrets.randbelow(q - 1) + 1


def elgamal_encrypt(pub: ElGamalPublicKey, m: int, r: int | None = None) -> Tuple[int, int]:
    """Encrypt a 0/1 message using ElGamal exponent encoding

    Args
    - pub: public key
    - m: message in {0,1}. For ballots, each option is encoded as a bit
    - r: optional randomness (for testing); sampled uniformly in [1 to q-1] if None

    Returns: tuple (c1, c2)
    """

    if m not in (0, 1):
        raise ValueError("This encryptor expects m in {0,1} (bit encoding).")
    params = pub.params

    if r is None:
        r = _rand_scalar(params.q)

    c1 = pow(params.g, r, params.p)
    c2 = (pow(pub.y, r, params.p) * pow(params.g, m, params.p)) % params.p
    
    return c1, c2


def elgamal_decrypt(priv: ElGamalPrivateKey, c: Tuple[int, int]) -> int:
    """Decrypt a ciphertext and return the bit m in {0,1}

    This recovers g^m and checks if it equals 1 (m=0) or g (m=1)
    """

    c1, c2 = c
    params = priv.params
    s = pow(c1, priv.x, params.p)
    # Inverse modulo p (p is prime). Using Fermat: s^(p-2) mod p
    s_inv = pow(s, params.p - 2, params.p)
    m_elem = (c2 * s_inv) % params.p

    if m_elem == 1:
        return 0
    
    if m_elem == params.g:
        return 1
    
    raise ValueError("Ciphertext does not decrypt to a valid bit.")


def ciphertext_mul(a: Tuple[int, int], b: Tuple[int, int], p: int) -> Tuple[int, int]:
    """Homomorphic multiplication of two ElGamal ciphertexts modulo p
    i.e,. math on encrypted data without first decrypting

    Enc(m1) * Enc(m2) = Enc(m1 + m2). Useful for tallying

    Args
    - a: First encrypted vote (as ciphertext) stored as (c1, c2)
    - b: Second encrypted vote (as ciphertext) stored as (c1, c2)
    - p: The large prime from ElGamalParams

    Returns
    - tuple (c1, c2): The resulting ciphertext representing the homomorphic sum of two input votes
    """

    return (a[0] * b[0]) % p, (a[1] * b[1]) % p


def discrete_log_small(base: int, value: int, p: int, max_k: int) -> int | None:
    """Brute-force discrete log for small ranges (0 to max_k)

    Intended for tallying counts up to the number of voters
    Returns k if base^k ≡ value (mod p), else None
    """

    cur = 1
    if value == 1:
        return 0
    
    for k in range(1, max_k + 1):
        cur = (cur * base) % p
        if cur == value:
            return k
        
    return None


def encode_ballot(ballot: Dict[str, str], options_map: Dict[str, List[str]]) -> Dict[str, List[int]]:
    """Encode a ballot into per-race 0/1 vectors

    Args
    - ballot: mapping race_id to selected option_id (string)
    - options_map: mapping race_id to ordered list of allowed option_ids

    Returns
    - dict race_id -> list of ints (0/1), exactly one '1' if a choice is present,
      otherwise all zeros (undervote)
    """

    encoded: Dict[str, List[int]] = {}
    for race_id, options in options_map.items():
        choice = ballot.get(race_id)
        vec = [0] * len(options)

        if choice is not None:
            try:
                idx = options.index(choice)
                vec[idx] = 1
            except ValueError:
                raise ValueError(f"Choice '{choice}' not in allowed options for race '{race_id}'.")
        encoded[race_id] = vec
    
    return encoded


def encrypt_ballot(pub: ElGamalPublicKey, encoded: Dict[str, List[int]]) -> Dict[str, List[Tuple[int, int]]]:
    """Encrypt a per-race 0/1-encoded ballot

    Args
    - pub: ElGamalPublicKey, the public key used to encrypt all ballots
    - encoded: A mapping of race IDs to lists of 0/1 integers

    Returns
    - dict: A mapping of race IDs to lists of ciphertexts, where each ciphertext is
            a tuple (c1, c2) representing the ElGamal encryption of one bit
    """

    out: Dict[str, List[Tuple[int, int]]] = {}
    for race_id, bits in encoded.items():
        out[race_id] = [elgamal_encrypt(pub, b) for b in bits]
    
    return out
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Tuple


def derive_voter_secret(voter_id: str, master_key: bytes) -> bytes:
    """Derive a per-voter secret using HMAC(master_key, voter_id)

    This avoids storing per-voter secrets in a database: the authority can
    recompute on demand given the master key
    """

    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    
    return hmac.new(master_key, voter_id.encode("utf-8"), hashlib.sha256).digest()


def build_auth_challenge(nbytes: int = 32) -> bytes:
    """Create a fresh random challenge for interactive authentication"""

    return secrets.token_bytes(nbytes)


def prove_auth(voter_secret: bytes, challenge: bytes) -> bytes:
    """Produce an HMAC proof over a challenge using the voter's secret"""

    return hmac.new(voter_secret, challenge, hashlib.sha256).digest()


def verify_auth_proof(voter_id: str, proof: bytes, challenge: bytes, master_key: bytes) -> bool:
    """Verify an HMAC-based challenge proof for a voter

    The authority recomputes the voter's secret from the master key and
    checks the provided HMAC
    """

    s_v = derive_voter_secret(voter_id, master_key)
    expected = hmac.new(s_v, challenge, hashlib.sha256).digest()

    return hmac.compare_digest(expected, proof)


def issue_vote_token(k_token: bytes, nbytes: int = 16) -> Tuple[str, str]:
    """Issue a fresh random token and its MAC

    Args
    - k_token: server-side secret key for token MACs
    - nbytes: token length (16-32 recommended for demos)

    Returns: (token_hex, mac_hex)
    """

    if not isinstance(k_token, (bytes, bytearray)):
        raise TypeError("k_token must be bytes")
    
    token = secrets.token_bytes(nbytes)
    mac = hmac.new(k_token, token, hashlib.sha256).hexdigest()
    
    return token.hex(), mac


def verify_vote_token(k_token: bytes, token_hex: str, mac_hex: str) -> bool:
    """Verify an HMAC for a presented token (server-side)"""

    try:
        token = bytes.fromhex(token_hex)
    except ValueError:
        return False
    
    expected = hmac.new(k_token, token, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac_hex)


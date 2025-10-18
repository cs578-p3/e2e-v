"""Reference implementations and outlines for protocol steps.

This module provides:
- step1_outline .. step4_outline: simple string outlines (documentation helpers)
- step5_process: a small tally function that accepts a list of ballots and returns counts
- step6_analyze: a verifier that compares a published tally to a recomputed tally

The implementations are intentionally simple and deterministic to make testing easy.
"""
from collections import Counter
from typing import List, Dict, Tuple, Any


def step1_outline() -> str:
    return (
        "Setup: generate election parameters, authority public keys, and a bulletin board."
    )


def step2_outline() -> str:
    return "Voter registration: enroll voters and issue credentials."


def step3_outline() -> str:
    return "Authentication: authenticate voters and issue short-lived voting tokens."


def step4_outline() -> str:
    return (
        "Ballot casting: voter constructs a ballot, (optionally) encrypts it and posts it to the bulletin board."
    )


def step5_process(ballots: List[Dict[str, Any]], choice_key: str = "choice") -> Dict[str, int]:
    """Tally ballots.

    Args:
        ballots: list of ballot records. Each ballot is expected to contain a key
            (by default 'choice') whose value is the voter's choice (string).
        choice_key: the key in the ballot dictionaries to read the choice from.

    Returns:
        A dictionary mapping choice -> count.

    Notes:
        - Invalid or missing choices are ignored (counted as 'invalid').
        - This is a reference implementation for prototyping only.
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
    return dict(counts)


def step6_analyze(published_tally: Dict[str, int], ballots: List[Dict[str, Any]], choice_key: str = "choice") -> Tuple[bool, Dict[str, Any]]:
    """Verify a published tally against the ballots.

    Args:
        published_tally: dictionary mapping choice -> count as published by authorities.
        ballots: list of ballots (same format as step5_process input).
        choice_key: key used to extract the voter choice from each ballot.

    Returns:
        (ok, details) where ok is True when published_tally matches recomputed tally
        (ignoring the special '__invalid__' key unless present in published_tally),
        and details contains the recomputed tally and any differences.
    """
    recomputed = step5_process(ballots, choice_key=choice_key)

    # Compare published vs recomputed for non-invalid keys
    keys = set(published_tally.keys()) | set(recomputed.keys())
    diffs = {}
    ok = True
    for k in keys:
        pub = int(published_tally.get(k, 0))
        rec = int(recomputed.get(k, 0))
        if pub != rec:
            diffs[k] = {"published": pub, "recomputed": rec}
            ok = False

    details = {"recomputed": recomputed, "diffs": diffs}
    return ok, details

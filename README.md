# e2e-v

## Overview

Design an end-to-end verifiable (E2E‑V) e‑voting protocol that allows voters to cast ballots from personal computers. The protocol must provide secrecy, authentication, and verifiability, while ensuring no one else can learn or prove how a particular voter voted.

## Learning goals

- Apply cryptographic primitives (encryption, signatures, zero-knowledge proofs, commitments).
- Develop a complete voting protocol that balances privacy and verifiability.
- Practice threat modeling and adversarial analysis.
- Communicate technical designs clearly through documentation and presentations.

## Required security properties

1) **Secrecy / Ballot privacy** — Votes remain private; no one can link a voter to their choice.
2) **Authentication** — Voters must authenticate securely before casting a vote.
3) **Individual verifiability** — Each voter can confirm their vote was recorded and counted correctly.
4) **Universal verifiability** — Anyone can verify the final tally based on published information.
5) **Receipt‑freeness (anti‑coercion)** — Voters cannot prove to others how they voted, reducing vote‑buying/coercion.
6) **Integrity** — Votes cannot be changed, removed, or added undetectably.

## Deliverables

- **Design Document (PDF)** — A clear description of the proposed protocol, including setup, authentication, ballot casting, tallying, and verification steps; address all required security properties.
- **Recorded Presentation** — Present the design, highlighting protocol steps, key security properties, and verifiability features.
- **Discussion of Trade‑offs** — If the design cannot fully achieve a property (e.g., full receipt‑freeness), explain limitations and possible improvements.

## Protocol steps (rough outline)

Below is a rough outline of the main protocol steps. Steps 1–4 are high-level sketches; steps 5–6 have a simple, testable reference implementation in `src/e2e_v/steps.py`.

1) Setup (Step 1)
- Goal: Establish system parameters, election configuration, public keys for authorities, and a bulletin board for publication.
- Inputs: Election metadata and cryptographic parameter choices.
- Outputs: Published election parameters and authority public keys.

2) Voter registration (Step 2)
- Goal: Enroll voters and issue credentials that will be used to authenticate for voting.
- Inputs: Voter identity assertions and eligibility lists.
- Outputs: Issued voter credentials and a (private) registry for authorities.

3) Authentication & Login (Step 3)
- Goal: Authenticate eligible voters and issue short-lived voting tokens or sessions.
- Inputs: Voter credential + authentication factors (OTP, password, etc.).
- Outputs: Short-lived token allowing the voter to cast a ballot.

4) Ballot creation & casting (Step 4)
- Goal: Voter creates a ballot, produces proofs as needed, and submits the (optionally encrypted) ballot to the bulletin board.
- Inputs: Voter choice(s), election parameters, randomness for encryption/commitments.
- Outputs: Submitted ballot entry and a voter-facing receipt.

5) Tallying (Step 5) — reference implementation
- A simple reference tallyer that counts choices from posted ballots is implemented in `src/e2e_v/steps.py`.

6) Verification (Step 6) — reference implementation
- A lightweight verification routine that recomputes the tally and reports mismatches is implemented in `src/e2e_v/steps.py`.

How to run the tests

1. Activate your virtual environment (if applicable) and run pytest from the repository root:

```powershell
# from repository root
python -m pytest -q
```

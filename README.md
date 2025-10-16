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

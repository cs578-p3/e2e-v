"""Simple runner that demonstrates steps 1-6 using the reference implementations.

Run this script from the repository root to see a tiny simulated election.
"""
from e2e_v import steps


def main():
    print("=== E2E-V Reference Runner ===")

    # Step 1: Setup (outline)
    print("\n[Step 1]", steps.step1_outline())

    # Step 2: Registration (outline)
    print("[Step 2]", steps.step2_outline())

    # Step 3: Authentication (outline)
    print("[Step 3]", steps.step3_outline())

    # Step 4: Ballot creation & casting (outline)
    print("[Step 4]", steps.step4_outline())

    # Simulate some ballots for steps 5 and 6
    ballots = [
        {"choice": "Alice"},
        {"choice": "Bob"},
        {"choice": "Alice"},
        {},  # invalid ballot
        {"choice": None},  # invalid ballot
    ]

    # Step 5: Tally
    published_tally = steps.step5_process(ballots)
    print("\n[Step 5] Published tally:")
    for choice, count in sorted(published_tally.items()):
        print(f"  {choice}: {count}")

    # Step 6: Verification
    ok, details = steps.step6_analyze(published_tally, ballots)
    print("\n[Step 6] Verification result:", "OK" if ok else "MISMATCH")
    if not ok:
        print("Differences:", details["diffs"])


if __name__ == "__main__":
    main()

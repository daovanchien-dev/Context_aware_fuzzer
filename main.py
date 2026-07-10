"""
Main entrypoint for Context-Aware & Feedback-Driven Web Fuzzer.

Phase 12:
- Gọi FuzzingEngine
- In summary
"""

import argparse
import sys


try:
    from core.fuzzing_engine import FuzzingEngine
except ImportError as error:
    print("Cannot import FuzzingEngine. Please run this command from project root.")
    print("Import error:", error)
    sys.exit(1)


def parse_args():
    """
    Parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Context-Aware & Feedback-Driven Web Fuzzer for RESTful API"
    )

    parser.add_argument(
        "--max-payloads-per-point",
        type=int,
        default=5,
        help="Maximum number of light payloads per injection point. Default: 5"
    )

    parser.add_argument(
        "--max-deep-payloads",
        type=int,
        default=3,
        help="Maximum number of deep payloads during escalation. Default: 3"
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="Reserved for future controlled concurrency. Default: 1"
    )

    return parser.parse_args()


def main():
    """
    Main function.
    """
    args = parse_args()

    engine = FuzzingEngine(
        max_payloads_per_point=args.max_payloads_per_point,
        max_deep_payloads=args.max_deep_payloads,
        max_workers=args.max_workers
    )

    summary = engine.run()

    print("\n Context-Aware Fuzzer Summary ")

    for key, value in summary.to_dict().items():
        print(f"{key}: {value}")

    if summary.errors:
        print("\nCompleted with controlled errors.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
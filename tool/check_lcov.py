#!/usr/bin/env python3
"""Fail if line coverage in an lcov file is below a threshold.

usage: check_lcov.py COVERAGE_FILE MIN_PERCENT
"""
import sys


def main() -> int:
    path, minimum = sys.argv[1], float(sys.argv[2])
    total = hit = 0
    with open(path) as lcov:
        for line in lcov:
            if line.startswith("DA:"):
                total += 1
                hit += int(line[3:].strip().split(",")[1]) > 0
    if total == 0:
        print(f"no coverage data in {path}")
        return 1
    percent = 100 * hit / total
    print(f"line coverage {percent:.1f}% ({hit}/{total}), minimum {minimum}%")
    return 0 if percent >= minimum else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Fail if an Xcode result bundle's line coverage for a source file is below a threshold.

usage: check_xccov.py RESULT_BUNDLE FILE_NAME MIN_PERCENT
Matches by file name (e.g. MobileHardeningKit.swift); every match must meet the threshold.
"""
import json
import subprocess
import sys


def main() -> int:
    bundle, name, minimum = sys.argv[1], sys.argv[2], float(sys.argv[3])
    report = json.loads(
        subprocess.check_output(["xcrun", "xccov", "view", "--report", "--json", bundle])
    )
    matches = [
        (target["name"], f)
        for target in report["targets"]
        for f in target["files"]
        if f["name"] == name
    ]
    if not matches:
        print(f"{name}: not found in coverage report")
        return 1
    failed = False
    for target, f in matches:
        percent = 100 * f["lineCoverage"]
        print(
            f"{target}/{name}: {percent:.1f}% "
            f"({f['coveredLines']}/{f['executableLines']}), minimum {minimum}%"
        )
        failed |= percent < minimum
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

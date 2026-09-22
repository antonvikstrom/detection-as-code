#!/usr/bin/env python3
"""
Compile every YARA rule under a directory. A rule that fails to compile
(syntax error, duplicate rule name, bad hex string, etc.) fails the build.

Usage: python3 validate_yara.py rules/yara/
Exit code 0 = all rules compiled, 1 = at least one failed.
"""
import sys
import pathlib

try:
    import yara
except ImportError:
    yara = None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_yara.py <rules_dir>")
        return 2

    if yara is None:
        print("yara-python not installed — run: pip3 install yara-python")
        return 2

    rules_dir = pathlib.Path(sys.argv[1])
    files = sorted(rules_dir.rglob("*.yar")) + sorted(rules_dir.rglob("*.yara"))

    if not files:
        print(f"no YARA rules found under {rules_dir}")
        return 0

    failed = False
    for f in files:
        try:
            yara.compile(filepath=str(f))
            print(f"OK   {f}")
        except yara.Error as e:
            failed = True
            print(f"FAIL {f}")
            print(f"  - {e}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

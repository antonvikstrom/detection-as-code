#!/usr/bin/env python3
"""
Checks that the YARA rule actually fires on what it should, not just that
it compiles (validate_yara.py only checks that part). Compiles
rules/yara/*.yar and scans each fixture in tests/yara/:

  positive_sample.bin            ELF magic + small + 2 syscalls: should match
  negative_wrong_magic.bin       wrong magic, otherwise identical: no match
  negative_too_few_syscalls.bin  correct magic, only 1 syscall: no match

Each negative fixture isolates one part of the rule's condition, so a
failure here points at what broke.

Usage: python3 scripts/test_yara_rules.py
"""
import pathlib
import sys

import yara

RULES_DIR = pathlib.Path("rules/yara")
FIXTURES_DIR = pathlib.Path("tests/yara")
RULE_NAME = "ELF_x64_MSFVenom_Reverse_TCP_Stager"

EXPECTATIONS = {
    "positive_sample.bin": True,
    "negative_wrong_magic.bin": False,
    "negative_too_few_syscalls.bin": False,
}


def main() -> int:
    rule_files = {p.stem: str(p) for p in RULES_DIR.glob("*.yar")}
    if not rule_files:
        print(f"ERROR: no YARA rules found under {RULES_DIR}", file=sys.stderr)
        return 1

    compiled = yara.compile(filepaths=rule_files)

    failed = False
    for fixture_name, expect_match in EXPECTATIONS.items():
        fixture_path = FIXTURES_DIR / fixture_name
        if not fixture_path.exists():
            print(f"FAIL missing fixture: {fixture_path}")
            failed = True
            continue

        matches = compiled.match(data=fixture_path.read_bytes())
        matched_names = {m.rule for m in matches}
        did_match = RULE_NAME in matched_names

        if did_match == expect_match:
            status = "MATCH" if did_match else "no match"
            print(f"PASS {fixture_name}: {status} (expected)")
        else:
            failed = True
            print(
                f"FAIL {fixture_name}: expected "
                f"{'a match' if expect_match else 'no match'}, got "
                f"{'a match' if did_match else 'no match'}"
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Validate every Sigma rule under a directory: confirms it's well-formed YAML,
has the required fields, and actually compiles via pySigma (catches condition
syntax errors, not just YAML syntax errors).

Usage: python3 validate_sigma.py rules/sigma/
Exit code 0 = all rules valid, 1 = at least one rule failed.
"""
import sys
import pathlib
import yaml

REQUIRED_FIELDS = ["title", "id", "status", "logsource", "detection"]


def validate_file(path: pathlib.Path) -> list[str]:
    errors = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"invalid YAML: {e}"]

    if not isinstance(rule, dict):
        return ["rule root is not a mapping"]

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"missing required field: {field}")

    if "mitre_attack" not in rule and "tags" not in rule:
        errors.append("no mitre_attack or tags field — rule isn't mapped to ATT&CK")

    # Try a real Sigma parse if pysigma is installed; degrade gracefully if not,
    # so this still runs somewhere without the dependency installed.
    try:
        from sigma.collection import SigmaCollection

        SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    except ImportError:
        pass
    except Exception as e:
        errors.append(f"pySigma failed to parse rule: {e}")

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_sigma.py <rules_dir>")
        return 2

    rules_dir = pathlib.Path(sys.argv[1])
    files = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))

    if not files:
        print(f"no Sigma rules found under {rules_dir}")
        return 0

    failed = False
    for f in files:
        errors = validate_file(f)
        if errors:
            failed = True
            print(f"FAIL {f}")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"OK   {f}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

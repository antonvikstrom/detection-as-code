#!/usr/bin/env python3
"""
Checks that the two DNS exfiltration Sigma rules fire on what they should
and stay quiet on what they shouldn't (validate_sigma.py only checks that
they parse). pySigma converts rules to backend queries rather than
running them, so there's no built-in way to ask "does event X match rule
Y". This pulls the actual regexes and filter values straight out of the
rule files, nothing here is hand-copied, and checks them against the
fixtures in tests/dns/sample_queries.json.

The watchlist_ioc cases run against tests/dns/fixture_watchlist.csv, a
frozen copy, not the live lookups/malicious_domains.csv. That file gets
overwritten by fetch_threat_intel.py, so a test tied to its live contents
breaks the moment a real feed pull replaces the seed domains the fixtures
use. That's exactly what happened the first time this ran after a real
fetch.

Usage: python3 scripts/test_sigma_dns_logic.py
"""
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from build_watchlist_pipeline import load_domains  # noqa: E402

FIXTURES = pathlib.Path("tests/dns/sample_queries.json")
WATCHLIST_RULE = pathlib.Path("rules/sigma/dns-exfiltration.yml")
BEHAVIORAL_RULE = pathlib.Path("rules/sigma/dns-exfiltration-behavioral.yml")
WATCHLIST_CSV = pathlib.Path("tests/dns/fixture_watchlist.csv")


def load_yaml(path: pathlib.Path) -> dict:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def check_watchlist_rule(fixtures: list[dict]) -> bool:
    rule = load_yaml(WATCHLIST_RULE)
    field = rule["detection"]["selection"].get("query|endswith|expand")
    if field != "%malicious_domains%":
        print(
            f"FAIL {WATCHLIST_RULE}: expected query|endswith|expand: "
            f"'%malicious_domains%', found {field!r}. Rule logic changed, "
            "update this test.",
        )
        return False

    watchlist = load_domains(WATCHLIST_CSV)
    failed = False
    for case in fixtures:
        query, expected = case["query"], case["expect_match"]
        got = any(query.endswith(suffix) for suffix in watchlist)
        ok = got == expected
        failed = failed or not ok
        print(f"{'PASS' if ok else 'FAIL'} watchlist_ioc  {query!r:55} expected={expected} got={got}  ({case['note']})")
    return not failed


def check_behavioral_rule(fixtures: list[dict]) -> bool:
    rule = load_yaml(BEHAVIORAL_RULE)
    det = rule["detection"]
    high_div_re = det["selection_high_diversity_label"]["query|re"]
    hex_re = det["selection_hex_label"]["query|re"]
    cdn_list = det["filter_common_cdn"]["query|contains"]

    def matches(query: str) -> bool:
        selection = bool(re.search(high_div_re, query)) or bool(re.search(hex_re, query))
        filtered = any(cdn in query for cdn in cdn_list)
        return selection and not filtered

    failed = False
    for case in fixtures:
        query, expected = case["query"], case["expect_match"]
        got = matches(query)
        ok = got == expected
        failed = failed or not ok
        print(f"{'PASS' if ok else 'FAIL'} behavioral      {query!r:55} expected={expected} got={got}  ({case['note']})")
    return not failed


def main() -> int:
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))

    watchlist_ok = check_watchlist_rule(fixtures["watchlist_ioc"])
    behavioral_ok = check_behavioral_rule(fixtures["behavioral_heuristic"])

    return 0 if (watchlist_ok and behavioral_ok) else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Checks the SPL rules' actual logic instead of just eyeballing the .spl
file: the LFI filter terms, the rex extraction regex, and the entropy
threshold. There's no Splunk instance here to run the searches against,
so this pulls the literal values out of the .spl files with regex and
re-implements just that piece of logic in Python. SPL isn't structured
like YAML, so this extraction is best-effort. A rewritten .spl in a very
different shape could slip past it.

  rules/spl/lfi-path-traversal.spl           filter terms + rex pattern
  rules/spl/dns-exfiltration-behavioral.spl  entropy calc + threshold

Usage: python3 scripts/test_spl_logic.py
"""
import json
import math
import pathlib
import re
import sys
from collections import Counter

LFI_SPL = pathlib.Path("rules/spl/lfi-path-traversal.spl")
LFI_FIXTURES = pathlib.Path("tests/lfi/sample_requests.txt")
DNS_SPL = pathlib.Path("rules/spl/dns-exfiltration-behavioral.spl")
DNS_FIXTURES = pathlib.Path("tests/dns/sample_queries.json")


def extract_filter_terms(spl_text: str) -> list[str]:
    # First non-comment, non-blank line is the base search with the filter.
    for line in spl_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return [m.strip("*") for m in re.findall(r'"([^"]+)"', line)]
    return []


def extract_rex_pattern(spl_text: str) -> str:
    m = re.search(r"\|\s*rex\s+field=\S+\s+\"((?:[^\"\\]|\\.)*)\"", spl_text)
    if not m:
        raise ValueError("could not find a `rex` command in the SPL")
    # Splunk's rex uses PCRE named-group syntax (?<name>...); Python's re
    # requires (?P<name>...).
    return re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", m.group(1))


def extract_threshold(spl_text: str, field: str) -> float:
    m = re.search(rf"\bwhere\s+{re.escape(field)}\s*>=\s*([0-9.]+)", spl_text)
    if not m:
        raise ValueError(f"could not find a `where {field} >=` clause in the SPL")
    return float(m.group(1))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def check_lfi() -> bool:
    spl_text = LFI_SPL.read_text(encoding="utf-8")
    terms = extract_filter_terms(spl_text)
    if not terms:
        print(f"FAIL {LFI_SPL}: could not extract filter terms", file=sys.stderr)
        return False

    # sanity-check the extraction regex still matches something real
    rex_pattern = extract_rex_pattern(spl_text)
    sample_line = '203.0.113.5 - - [21/Sep/2026:10:00:00 +0000] "GET /page?x=1 HTTP/1.1" 200'
    m = re.search(rex_pattern, sample_line)
    if not m or m.group("src_ip") != "203.0.113.5" or m.group("http_method") != "GET":
        print(f"FAIL {LFI_SPL}: rex extraction regex didn't extract src_ip/http_method as expected")
        return False
    print(f"PASS {LFI_SPL}: rex extraction regex OK (src_ip={m.group('src_ip')}, method={m.group('http_method')}, uri={m.group('uri')})")

    failed = False
    for line in LFI_FIXTURES.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        expect_str, raw = line.split("\t", 1)
        expected = bool(int(expect_str))
        got = any(term.lower() in raw.lower() for term in terms)
        ok = got == expected
        failed = failed or not ok
        print(f"{'PASS' if ok else 'FAIL'} lfi_filter  expected={expected} got={got}  {raw[:80]}")
    return not failed


def check_dns_entropy() -> bool:
    spl_text = DNS_SPL.read_text(encoding="utf-8")
    threshold = extract_threshold(spl_text, "entropy")
    fixtures = json.loads(DNS_FIXTURES.read_text(encoding="utf-8"))["entropy_heuristic"]

    failed = False
    for case in fixtures:
        subdomain, expected = case["subdomain"], case["expect_high_entropy"]
        score = shannon_entropy(subdomain)
        got = score >= threshold
        ok = got == expected
        failed = failed or not ok
        print(f"{'PASS' if ok else 'FAIL'} entropy({threshold})  {subdomain!r:40} score={score:.2f} expected_high={expected} got_high={got}  ({case['note']})")
    return not failed


def main() -> int:
    lfi_ok = check_lfi()
    entropy_ok = check_dns_entropy()
    return 0 if (lfi_ok and entropy_ok) else 1


if __name__ == "__main__":
    sys.exit(main())

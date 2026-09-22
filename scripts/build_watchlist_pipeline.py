#!/usr/bin/env python3
"""
Builds the pySigma pipeline that resolves the %malicious_domains%
placeholder in rules/sigma/dns-exfiltration.yml
(query|endswith|expand: '%malicious_domains%') from the current contents
of lookups/malicious_domains.csv. The CSV is refreshed on a schedule by
.github/workflows/update-watchlist.yml, so converting the rule against a
fresh checkout always reflects the latest feed pull, no rule edit needed.
Feed this pipeline into `sigma convert` (sigma-cli) with a backend plugin
for a real SIEM query, e.g.:

    sigma convert -t splunk -p scripts/build_watchlist_pipeline.py \\
        rules/sigma/dns-exfiltration.yml

Domains are stored bare in the CSV ("evil.com") and expanded here to a
leading-dot suffix (".evil.com"), so the rule matches subdomains without
also matching on a substring like "notevil.com".

Usage as a library:
    from build_watchlist_pipeline import build_pipeline
    pipeline, domains = build_pipeline("lookups/malicious_domains.csv")

Usage standalone, as a CI check that the watchlist isn't empty (an empty
watchlist makes the IOC-match rule a silent no-op):
    python3 scripts/build_watchlist_pipeline.py lookups/malicious_domains.csv
"""
import csv
import pathlib
import sys

PLACEHOLDER_NAME = "malicious_domains"


def load_domains(csv_path: pathlib.Path) -> list[str]:
    if not csv_path.exists():
        return []
    domains = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = (row.get("domain") or "").strip().lstrip("*").lstrip(".")
            if domain:
                domains.append(f".{domain}")
    return domains


def build_pipeline(csv_path: str = "lookups/malicious_domains.csv"):
    # Imported lazily so load_domains() (the CSV-parsing logic tests actually
    # exercise) stays importable without pysigma installed.
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import ValueListPlaceholderTransformation

    domains = load_domains(pathlib.Path(csv_path))
    pipeline = ProcessingPipeline(
        name="watchlist-placeholder-resolution",
        priority=10,
        items=[
            ProcessingItem(
                transformation=ValueListPlaceholderTransformation(
                    {PLACEHOLDER_NAME: domains}
                ),
            )
        ],
    )
    return pipeline, domains


def main() -> int:
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "lookups/malicious_domains.csv"
    _, domains = build_pipeline(csv_path)

    print(f"loaded {len(domains)} domain(s) from {csv_path}")
    if not domains:
        print(
            "WARNING: watchlist is empty, the IOC-match rule currently "
            "matches nothing. Run scripts/fetch_threat_intel.py.",
            file=sys.stderr,
        )
        return 1

    for d in domains[:10]:
        print(f"  {d}")
    if len(domains) > 10:
        print(f"  ... and {len(domains) - 10} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Pulls recent malicious URLs from abuse.ch URLhaus, extracts the
hostnames, and writes them to this repo's threat-intel watchlist in
two forms:

  lookups/malicious_domains.csv          canonical: bare domain
  lookups/malicious_domains_splunk.csv   "*.domain", for Splunk's wildcard
                                          lookup (see
                                          lookups/transforms.conf.example)

URLhaus requires a free Auth-Key (https://auth.abuse.ch/) for dataset
downloads. The old unauthenticated endpoint (/downloads/csv_recent/) was
retired in Oct 2026 and now returns 410 Gone. The key is read from the
URLHAUS_AUTH_KEY environment variable (a repository secret in GitHub
Actions; export it in your shell when running locally).

.github/workflows/update-watchlist.yml runs this on a schedule so
rules/sigma/dns-exfiltration.yml (via build_watchlist_pipeline.py) and
rules/spl/dns-exfiltration.spl match against a live feed instead of a
hardcoded domain. Each scheduled run is a commit, so the file's git
history doubles as a log of what counted as known-bad at any point.

On failure (missing key, network error, empty feed) this leaves the
existing lookup files alone and exits non-zero, so a bad feed pull can't
quietly empty out the watchlist.

Usage: URLHAUS_AUTH_KEY=... python3 scripts/fetch_threat_intel.py [--limit 500] [--feed-url URL]
"""
import argparse
import csv
import os
import pathlib
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# The Auth-Key is part of the URL path, so never print this URL or a raw
# exception that might contain it.
FEED_URL_TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
CANONICAL_OUT = pathlib.Path("lookups/malicious_domains.csv")
SPLUNK_OUT = pathlib.Path("lookups/malicious_domains_splunk.csv")
FIELDNAMES = ["domain", "first_seen", "source"]

# Legit platforms abused to host payloads: matching on them in DNS is pure
# noise. Catch these at URL level instead.
ALLOWLIST = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "drive.google.com", "docs.google.com",
    "storage.googleapis.com", "dropbox.com", "dl.dropboxusercontent.com",
    "cdn.discordapp.com", "onedrive.live.com", "1drv.ms", "pastebin.com",
}

def fetch_domains(feed_url: str, limit: int) -> list[dict]:
    resp = requests.get(feed_url, timeout=30)
    resp.raise_for_status()

    seen: dict[str, dict] = {}
    for line in resp.text.splitlines():
        if not line or line.startswith("#"):
            continue
        # URLhaus recent.csv columns:
        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        fields = next(csv.reader([line]))
        if len(fields) < 6:
            continue
        date_added, url, threat = fields[1], fields[2], fields[5]
        host = urlparse(url).hostname
        if not host or host.replace(".", "").isdigit():
            # skip unparseable entries and bare-IP URLs, not DNS-relevant
            continue
        host = host.lower().strip(".")
        if host in ALLOWLIST or any(host.endswith("." + d) for d in ALLOWLIST):
            continue
        if host not in seen:
            seen[host] = {
                "domain": host,
                "first_seen": date_added.split(" ")[0] if date_added else "",
                "source": f"abuse.ch URLhaus ({threat or 'malware_download'})",
            }
        if len(seen) >= limit:
            break

    return list(seen.values())


def write_csv(rows: list[dict], path: pathlib.Path, wildcard: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            out = dict(row)
            if wildcard:
                out["domain"] = f"*.{row['domain']}"
            writer.writerow(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=500, help="max unique domains to keep")
    parser.add_argument(
        "--feed-url",
        default=None,
        help="override the feed URL; by default it is built from URLHAUS_AUTH_KEY",
    )
    args = parser.parse_args()

    feed_url = args.feed_url
    if not feed_url:
        key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
        if not key:
            print(
                "ERROR: URLHAUS_AUTH_KEY is not set (get a free key at "
                "https://auth.abuse.ch/)",
                file=sys.stderr,
            )
            print("leaving existing lookup files untouched", file=sys.stderr)
            return 1
        feed_url = FEED_URL_TEMPLATE.format(key=key)

    try:
        rows = fetch_domains(feed_url, args.limit)
    except requests.RequestException as e:
        # Don't print e itself: its message includes the URL, and the URL
        # includes the Auth-Key.
        status = getattr(e.response, "status_code", None) or "n/a"
        print(
            f"ERROR: failed to fetch threat-intel feed (HTTP {status}, {type(e).__name__})",
            file=sys.stderr,
        )
        print("leaving existing lookup files untouched", file=sys.stderr)
        return 1

    if not rows:
        print(
            "ERROR: feed returned zero usable domains, refusing to overwrite "
            "the watchlist with an empty one",
            file=sys.stderr,
        )
        return 1

    write_csv(rows, CANONICAL_OUT, wildcard=False)
    write_csv(rows, SPLUNK_OUT, wildcard=True)
    print(
        f"wrote {len(rows)} domain(s) to {CANONICAL_OUT} and {SPLUNK_OUT} "
        f"as of {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
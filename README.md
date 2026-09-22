# Detection-as-Code

This repo holds detection logic (Sigma, YARA, and SPL rules) kept in version control. Some basic checks run automatically in CI. Every rule gets checked when it's pushed or opened as a pull request, before it's allowed to merge.

It brings together detections I'd originally built across a few other projects:
- `building-secure-home-lab`: network/AD telemetry baselines
- `automated-threat-detection-pipeline`: web/DNS exfiltration detections
- `dfir-malware-analysis-lab`: YARA signatures from live malware analysis
- `soar-automation-pipeline`: enrichment and response-triggering logic

## Why detection-as-code

A detection that only lives inside a SIEM's web UI doesn't have much of a paper trail. No version history, no review step, no proof it still works after a platform update. Treating detections like code fixes that: reviewed through a pull request, checked in CI, tested against sample data. This seems to be fairly common practice on more established detection engineering teams. It also felt like a clear way to show that kind of discipline in a portfolio, even if this repo is still a small example of it.

## Structure

```
detection-as-code/
├── rules/
│   ├── sigma/      # Sigma rules (YAML); platform-agnostic, convertible to SPL/KQL/etc.
│   ├── yara/        # YARA rules; file/memory-based malware signatures
│   └── spl/         # Splunk SPL searches; Splunk-specific, not covered by the linters below
├── lookups/          # Threat-intel watchlist CSVs used by the IOC-match rules (see below)
├── scripts/          # Validation + detection-logic tests, plus the watchlist fetch/pipeline scripts
├── tests/            # Small labeled examples each rule should and shouldn't fire on (see "Testing")
└── .github/workflows/
    ├── lint.yml               # CI: checks every rule on push/PR
    └── update-watchlist.yml   # CI: refreshes the threat-intel watchlist once a day
```

## Current rules

| Rule | Format | Type | MITRE ATT&CK | Ported from |
| --- | --- | --- | --- | --- |
| LFI / path traversal against web application | SPL | Behavioral | T1190, T1083 | `automated-threat-detection-pipeline` |
| DNS exfiltration via watchlisted domain | SPL + Sigma | IOC match (live watchlist) | T1071.004, T1048.003 | `automated-threat-detection-pipeline` |
| DNS exfiltration via high-entropy/long subdomain labels | SPL + Sigma | Behavioral | T1071.004, T1048.003 | Written for this repo |
| ELF x64 MSFVenom reverse TCP stager | YARA | Behavioral (magic bytes + filesize + syscall heuristic) | T1059.004, T1571 | `dfir-malware-analysis-lab` |

The DNS exfiltration detection exists in both SPL and Sigma on purpose. The Sigma version is meant to be platform-agnostic: it could, in theory, convert to Splunk, Sentinel/KQL, or Elastic through a Sigma backend converter. The SPL version is closer to what's actually running in the lab today. That's roughly what detection-as-code is about, in miniature: write the logic once instead of maintaining it by hand on every platform.

### IOC match vs. behavioral detection

The two DNS exfiltration rules differ in a more basic way than just their logic, so it seemed worth spelling out:

- **IOC match** (`dns-exfiltration.yml` / `.spl`) checks a domain against a threat-intel watchlist (see [Threat-intel watchlist](#threat-intel-watchlist) below). This is a pretty standard way to detect things. But it can only catch domains someone has already reported as bad.
- **Behavioral** (`dns-exfiltration-behavioral.yml` / `.spl`) looks at the shape of a DNS query instead of matching a known domain: subdomain length, how "random" the characters look. That should generalize to a domain nobody's seen before. It probably needs real tuning first, though (thresholds, an allowlist for things like CDNs) before it'd hold up outside a lab.

I think both approaches are worth having here. The mistake would be treating the IOC match as if it generalizes to unknown threats, when it doesn't.

## Threat-intel watchlist

The IOC-match DNS rule doesn't check against a domain typed into the rule itself. It checks against a small watchlist that's pulled from a live feed and refreshed on its own:

1. `scripts/fetch_threat_intel.py` pulls recently-reported malicious URLs from [abuse.ch URLhaus](https://urlhaus.abuse.ch/) (free, no API key needed), pulls out the hostnames, and writes them to `lookups/malicious_domains.csv` (plain domain) and `lookups/malicious_domains_splunk.csv` (same data, written as `*.domain` for Splunk's wildcard lookup matching).
2. `.github/workflows/update-watchlist.yml` runs that script once a day, and can also be run by hand. It commits the refreshed CSVs back to the repo if anything changed, so the git history of that file ends up being a rough log of what counted as "known bad" at any given time. If the feed fails, the script leaves the existing files alone instead of committing an empty watchlist.
3. **On the Sigma side:** `rules/sigma/dns-exfiltration.yml` uses a `%malicious_domains%` placeholder (`query|endswith|expand: '%malicious_domains%'`) instead of a literal value. `scripts/build_watchlist_pipeline.py` builds the pySigma pipeline that fills in that placeholder from the current CSV. Feeding that into `sigma convert` with a backend plugin should produce a real, up-to-date query. CI also runs this script as a quick sanity check, and fails the build if the watchlist is empty. A rule with nothing loaded in it would just quietly match nothing, which seemed worse than an obviously broken build.
4. **On the SPL side:** `rules/spl/dns-exfiltration.spl` uses Splunk's `lookup` command against a `malicious_domains_splunk_lookup` definition (see `lookups/transforms.conf.example` for that config). The important bit is `match_type = WILDCARD(domain)`. That's what lets an entry like `*.evil.com` match any subdomain instead of only an exact string.

Swapping the feed for something else (ThreatFox, MISP, a paid CTI feed) should only mean changing the parsing logic in `fetch_threat_intel.py`. The rules and the pipeline that resolves them shouldn't need to change.

## Rule metadata convention

Every rule's front matter is meant to include:
- `title` / rule name
- `id` (a UUID for Sigma; the rule name for YARA)
- `status`: `experimental` | `test` | `stable`
- `mitre_attack`: one or more technique IDs (e.g. `T1071.004`)
- `references`: a link back to where the detection was originally developed (e.g. the relevant lab's README)

## Adding a rule

1. Drop the rule file into the right subfolder under `rules/`.
2. Fill in the metadata fields above.
3. If the logic seems important enough that it could break silently, add a small example or two under `tests/` and a case to the matching test script. A rule that still parses but has quietly stopped matching what it claims to seems like a worse failure than one that just fails to compile.
4. Open a PR. CI checks Sigma rules for valid syntax/schema, compiles YARA rules to catch syntax errors, and runs the detection-logic tests below. A rule that doesn't parse, or no longer matches its own examples, fails the build.
5. Once it's merged, it might be worth considering whether the rule is general enough to also submit upstream to [SigmaHQ](https://github.com/SigmaHQ/sigma). A merged public PR there is probably a stronger signal than the rule just sitting in this repo.

## Testing that this actually works

There seem to be two different questions worth asking here, and it's easy to mix them up:

- **Does it parse?** `validate_sigma.py` and `validate_yara.py` answer this one. A rule with valid syntax that never actually matches anything is still a broken detection. Passing this check is necessary, but not enough on its own.
- **Does it fire on what it's supposed to, and stay quiet on what it shouldn't?** `test_yara_rules.py`, `test_sigma_dns_logic.py`, and `test_spl_logic.py` try to answer this one. They pull each rule's actual logic straight out of the rule files, rather than it being retyped by hand somewhere, so it can't drift out of sync. Then they run it against small labeled examples under `tests/`: something malicious that should match, something benign that shouldn't, and at least one edge case per rule (a domain that looks similar but shouldn't match, a CDN that should be allowed through, a mixed-encoding LFI payload that's a known gap rather than something falsely claimed to be covered). Writing these is actually how the mixed-encoding gap in the LFI rule got noticed. There's a comment about it near the bottom of `tests/lfi/sample_requests.txt` if that's of interest.

```bash
pip3 install -r requirements.txt

# does it parse?
python3 scripts/validate_sigma.py rules/sigma/
python3 scripts/validate_yara.py rules/yara/

# does it actually detect what it's supposed to?
python3 scripts/test_yara_rules.py
python3 scripts/test_sigma_dns_logic.py
python3 scripts/test_spl_logic.py

# is the live threat-intel watchlist actually populated?
python3 scripts/fetch_threat_intel.py                              # pulls from abuse.ch URLhaus
python3 scripts/build_watchlist_pipeline.py lookups/malicious_domains.csv
```

These are the same checks CI runs (`lint.yml`'s `lint-sigma`, `lint-yara`, and `test-detections` jobs) on every push and PR, plus `update-watchlist.yml` once a day. So a green check on GitHub is hopefully real evidence of something working, not just "it built."

The SPL rules can't actually be run here, since there's no Splunk instance in CI. So `test_spl_logic.py` is more of a best-effort stand-in: it pulls the literal filter terms, extraction regex, and entropy threshold out of the `.spl` files with regex, and re-implements just that piece of logic in Python instead of really running the search. It should catch a broken regex or a threshold that got typed wrong. It probably won't catch every way a Splunk-specific command could behave differently from its Python equivalent.

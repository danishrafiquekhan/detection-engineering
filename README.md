# Detection Engineering

**Status: in progress** — this repo tracks detection rules as I build them through a structured detection-engineering study plan. It is personal lab work, not a production rule set.

## What this is
Sigma rules and their Microsoft Sentinel (KQL) conversions, mapped to MITRE ATT&CK, covering identity and cloud-account abuse scenarios.

## Why I built it
To practice writing detections the way a detection-engineering team actually works: rule → data source → ATT&CK technique → validation status, rather than one-off scripts.

## How it works
- `sigma-rules/` — vendor-agnostic Sigma YAML rules
- `kql-conversions/` — the same logic translated to KQL for Sentinel
- `attack-mapping.csv` — Rule → ATT&CK Technique → Data Source → Status

## What I learned / trade-offs
_(filled in as rules are added — the point of this section is to show judgment, not just list rules)_

## Security note
No real tenant IDs, subscription IDs, credentials, or organisational log data are committed here. Sample values are placeholders (e.g. `<your-tenant-id>`).

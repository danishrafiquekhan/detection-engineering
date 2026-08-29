# Detection Engineering

**Status: in progress** — this repo tracks detection rules as I build them through a structured detection-engineering study plan. It is personal lab work, not a production rule set.

## What this is
Sigma rules and their Microsoft Sentinel (KQL) conversions, mapped to MITRE ATT&CK, covering identity and cloud-account abuse scenarios.

## Why I built it
To practice writing detections the way a detection-engineering team actually works: rule → data source → ATT&CK technique → validation status, rather than one-off scripts.

## How it works
- `sigma-rules/` — vendor-agnostic Sigma YAML rules
- `kql-conversions/pipelines/` — a custom [pySigma](https://github.com/SigmaHQ/pySigma) processing pipeline that maps `authentication`/`azure`/`signinlogs` rules onto the Sentinel `SigninLogs` table (the built-in `sentinel_asim` pipeline doesn't auto-map that category, so this fills the gap)
- `kql-conversions/generated/` — the KQL output, ready to paste into a Sentinel Log Analytics workspace
- `attack-mapping.csv` — Rule → ATT&CK Technique → Data Source → Status
- `Makefile` — `make convert` regenerates every `.kql` file from the Sigma sources using [sigma-cli](https://github.com/SigmaHQ/sigma-cli) + the `sentinelasim`/`kusto` plugins

To reproduce locally: `pipx install sigma-cli && sigma plugin install kusto`, then `make convert` from this directory.

## What I learned / trade-offs
The `sentinel_asim` pipeline only auto-resolves the target table for a handful of built-in categories (e.g. `network_connection`) — anything else needs the table set explicitly via pipeline state, or conversion fails with "unable to determine table name." Wrote a 10-line custom pipeline (`kql-conversions/pipelines/signinlogs-table.yml`) using `set_state` at a lower priority number so it runs before `sentinel_asim`'s own check. These two rules are converted and validated for syntax, but not yet deployed against a live Sentinel workspace — that's the next step once the Azure lab is up (see `sentinel-soar-playbooks` and `terraform-labs`).

## Security note
No real tenant IDs, subscription IDs, credentials, or organisational log data are committed here. Sample values are placeholders (e.g. `<your-tenant-id>`).

## Running a local SIEM for free
`local-lab/` sets up a self-hosted, open-source Wazuh SIEM in Docker — no Azure subscription needed to have something real running. See `local-lab/README.md`.

## One-time setup after cloning
```bash
git config core.hooksPath .githooks   # enables the gitleaks secret-scan on commit
```

# detection-engineering

Sigma rules mapped to ATT&CK, converted to KQL for Sentinel. This is the core of the study plan everything else in my portfolio kind of orbits around it.

I'm doing it this way (Sigma first, KQL second) on purpose. Writing the detection logic in Sigma forces me to think about the actual condition separately from "how do I query this in KQL," and it means the same rule could theoretically target Splunk or Elastic later without rewriting the logic from scratch. Whether that portability ever matters for me personally, I don't know yet — but it's how real detection engineering teams do it, so I'm doing it too.

## What's in here

- `sigma-rules/`: 8 rules right now, covering sign-in abuse, Entra ID audit log tampering, M365 exfiltration, and one endpoint rule (PowerShell)
- `kql-conversions/pipelines/azuread-table-mappings.yml` a small pySigma pipeline I had to write myself
- `kql-conversions/generated/`: the actual KQL, one file per rule
- `attack-mapping.csv` — rule, technique, data source, status, in one table
- `Makefile`: `make convert` regenerates everything
- `llm-triage/` : two scripts that use Claude to summarize alerts and draft incident timelines
- `local-lab/` : Wazuh, running locally, because I'm not paying for a Sentinel workspace just to test rule syntax
- `docs/`, the full test case catalog and lab guide, tracking what's actually built across the whole plan

To run it yourself: `pipx install sigma-cli && sigma plugin install kusto`, then `make convert`.

## The pipeline problem

The built-in `sentinel_asim` pipeline that ships with sigma-cli only knows how to map a handful of log categories to their Sentinel table automatically things like `network_connection`. Anything outside that list and conversion just fails with "unable to determine table name from rule," which took me a minute to figure out wasn't a bug in my rule, it's just that Entra ID sign-in/audit logs aren't in its default list.

Fix was a ~15-line pipeline file that sets the table name explicitly before `sentinel_asim` runs its own checks has to run at a lower priority number so it goes first. Covers `SigninLogs`, `AuditLogs`, and `OfficeActivity` now. If I add more rule categories later I'll probably need to extend this again.

## Where Sigma actually falls short

`password-spray.yml` is the one that exposed this: a password spray is defined by *aggregation* — many different accounts failing from one source in a short window — and Sigma's single-rule spec genuinely has no way to express "count distinct X grouped by Y." So the Sigma rule only captures the per-event condition (the failure codes), and the aggregation (`summarize`, `dcount`, the 10-minute bucket) is hand-written directly into the generated KQL file, with a comment explaining why. I don't love that the two files can drift apart if I'm not careful, but I haven't found a cleaner way to do it within plain Sigma.

One annoyance: `sigma check` just hangs forever on my machine — seems to try to validate ATT&CK tags against attack.mitre.org and never comes back. I gave up waiting on it and use `make convert` instead, which parses every rule anyway as a side effect of converting it.

## Honest state of things

All 8 rules convert cleanly and are syntactically valid. None of them have run against a real Sentinel workspace with real sign-in data yet, so "compiles" is not the same claim as "works". I don't have a tenant with actual traffic to test false-positive rates against. That's the next real milestone, not this one.

No real tenant IDs, subscription IDs, or actual log data anywhere in this repo — everything's a placeholder or synthetic.

## One-time setup after cloning
```bash
git config core.hooksPath .githooks
```
This turns on a gitleaks scan before every commit. Doesn't catch everything (found that out the hard way a password string with a `$` in it slipped right past it once), but it's a decent backstop.

**Actually running the KQL, not just checking it parses**

`log-correlation/` already re-implements each rule's logic in Python against fixture data — a real, useful check that the *logic* is right, and it already caught one real gap ([`conditional-access-policy-tampering`](../../log-correlation/README.md#what-this-caught)). This is a different, complementary check: does the *actual `.kql` file text* — byte for byte what would run in a real Sentinel workspace — execute correctly against a real Kusto query engine? That's a gap Python re-implementation can't close on its own, since a hand-written Python reimplementation could be right while the real KQL syntax next to it has a typo, a wrong operator, or a column-name mismatch that would only surface at actual query time.

**How**

[Microsoft's own Kusto emulator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto-emulator-install) (`kustainer`, a free Docker image, no Azure subscription needed) runs the real Kusto query engine locally. `setup_schema.kql` creates `SigninLogs`, `AuditLogs`, `OfficeActivity`, and `imProcessCreate` tables matching the columns each of the 8 generated rules actually reference. `synthetic_data.kql` ingests rows built specifically to include both cases that should fire and cases that should not, for every rule. `run_verification.py` then loads each real `.kql` file from `kql-conversions/generated/` (stripping only comments, nothing else) and executes it against the emulator over its HTTP query endpoint, reporting real row counts and real matched rows.

**Result: all 8 rules execute without error against a real Kusto engine**

Every rule ran clean — no syntax errors, no column-resolution errors, no type errors. `evidence/verification-run-output.txt` is the real, complete output of that run.

**What this run found and fixed for real: `suspicious-signin-velocity` had no aggregation logic at all**

Already flagged honestly in `log-correlation/README.md` as "a known-noisy rule by design" — its Sigma title promises impossible-travel-style detection, but its actual condition was just `ResultType == 0`, every successful sign-in. Verified here concretely: against 13 synthetic sign-in rows, it matched all 3 successful ones, including two entirely ordinary logins with no velocity signal at all.

Unlike `password-spray.yml` (which documents this same Sigma limitation and has the aggregation added by hand in its `.kql` file), `suspicious-signin-velocity` never got that second layer — an oversight, not a deliberate design choice like `mass-file-download`'s documented high-FP tradeoff. Fixed for real this time: `sigma-rules/suspicious-signin-velocity.yml`'s description now documents the same Sigma limitation `password-spray.yml` does, and `kql-conversions/generated/suspicious-signin-velocity.kql` now has a `summarize`/`dcount` aggregation matching the same pattern — same account, 2+ distinct countries, 30-minute window. Re-verified against synthetic data built specifically to prove selectivity: fires once, correctly, only for the account signing in from two countries ten minutes apart; does not fire for an account signing in from the same country twice, or for any of the single-event rows.

**What this run did *not* newly discover, and did not fix**

- `conditional-access-policy-tampering`'s gap against real Microsoft `ModifiedProperties` formatting was already found by `log-correlation/`, not by this. The synthetic data used here for that rule matches the rule's own (possibly incorrect) assumed format, the same limitation `log-correlation/README.md` already documents — so this rule executing cleanly here is *not* new evidence it would fire against a real tenant's actual audit log shape. Left unfixed here for the same reason `log-correlation/` left it unfixed: the exact real format needs confirming against a real tenant capture, not assumed from documentation.
- `mass-file-download`'s high false-positive-by-design status (already in `attack-mapping.csv`) is unchanged — this run confirms the logic does what it says, not that what it says is low-noise.
- `suspicious-powershell-execution` targets `imProcessCreate`, Microsoft Sentinel's ASIM-normalized process-creation table. The emulator has no ASIM parser function, so this run created a plain table with the two columns the rule needs rather than exercising real ASIM normalization — this proves the rule's own filter condition works, not that ASIM normalization itself would feed it correctly.

**What this still doesn't prove**

Same honest boundary `log-correlation/README.md` already draws: synthetic data shaped like the real schema is not the same as real traffic at real volume with real edge cases. No false-positive rate against genuine noise, no performance characteristics, nothing about how Sentinel's actual analytics-rule scheduling or entity mapping would behave. Getting real Entra/Sentinel data remains the actual next milestone — this closes the smaller, immediate gap between "the KQL text is believed correct" and "the KQL text has actually been executed by a real Kusto engine and does what it claims," for free, without needing that tenant first.

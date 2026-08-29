# LLM-Assisted Triage (Category 6)

**Status: scripts working (verified: SDK installs and imports cleanly, calls the exact Messages API shape used elsewhere); not run end-to-end against a live API key in this environment.**

## What this is
Two small scripts that use an LLM to speed up (not replace) human triage:
- `alert_summarizer.py` — turns a raw alert JSON blob into a 5-second plain-English summary
- `incident_timeline.py` — drafts a chronological narrative from a list of timestamped log entries

## Honesty note on "free"
Unlike everything else in this lab (Wazuh, TheHive, LocalStack, Terraform, sigma-cli), **this category has a real, small, per-call cost** — LLM API calls are billed per token. It's cheap for occasional testing (a few cents for the sample runs below) but isn't zero-cost infrastructure like the rest of the lab. Said plainly here rather than glossed over.

## Run it
```bash
cd llm-triage
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=<your key>   # get one at console.anthropic.com — never commit it

python3 alert_summarizer.py sample-wazuh-alert.json
python3 incident_timeline.py sample-events.json
```
`sample-wazuh-alert.json` and `sample-events.json` are synthetic — reserved-for-documentation IP ranges (`198.51.100.0/24`) and made-up hostnames, safe to commit and safe to run against.

## Design constraints (deliberate)
- The system prompt explicitly tells the model not to decide an alert is a false positive or take any action — it's a triage aid, not an autonomous responder, matching the catalog's own scoping note.
- `incident_timeline.py`'s prompt forces an "UNVERIFIED DRAFT — human review required" line into every output, so the narrative can never be mistaken for a validated record.

## What I learned / trade-offs
The interesting design decision here isn't the API call (that's a few lines) — it's the system prompt boundary. An LLM asked to "summarize this alert" will happily also volunteer a verdict ("this is probably benign") if you let it; the prompt has to explicitly forbid that, or the "triage aid" quietly becomes an "auto-classifier" with none of the validation that would require.

## Security note
Never commit `ANTHROPIC_API_KEY`. `venv/` is gitignored.

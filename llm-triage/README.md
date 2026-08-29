# LLM-assisted triage

Two small scripts, both using Claude:
- `alert_summarizer.py` — reads a raw alert JSON and spits out a summary an analyst can actually read in 5 seconds instead of parsing the raw fields
- `incident_timeline.py` — takes a list of timestamped events and drafts them into a narrative

This isn't automation replacing a human, it's a triage aid. Important distinction and I built the prompts around enforcing it.

## Cost, honestly
Everything else in this portfolio (Wazuh, TheHive, LocalStack, Terraform) is genuinely free. This isn't — API calls cost a small amount per token. Not going to pretend otherwise just because the rest of the lab is free. It's cheap to test with (fractions of a cent per call for something this small) but it's not zero.

## Running it
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=<your key>

python3 alert_summarizer.py sample-wazuh-alert.json
python3 incident_timeline.py sample-events.json
```
The sample JSON files use made-up hostnames and the `198.51.100.0/24` range that's reserved specifically for documentation examples — nothing real in there, safe to run against.

## Why the prompts are written the way they are
First draft of the summarizer prompt just said "summarize this alert." Turns out an LLM asked to summarize an alert will also happily hand you a verdict you didn't ask for — "this looks benign," "probably a false positive" — which is exactly the kind of thing a triage *aid* shouldn't be doing on its own. Had to explicitly tell it not to decide anything or recommend an action. Same idea in the timeline script — it's forced to end every output with an "UNVERIFIED DRAFT, human review required" line so nobody downstream mistakes a first-pass narrative for something validated.

Small thing, but it's the actual design decision here. The API call itself is maybe five lines.

Don't commit `ANTHROPIC_API_KEY`. `venv/` is gitignored.

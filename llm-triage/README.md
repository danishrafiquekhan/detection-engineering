**LLM-assisted triage**

Three small scripts, all using Claude:
- `alert_summarizer.py` — reads a raw alert JSON and spits out a summary an analyst can actually read in 5 seconds instead of parsing the raw fields
- `incident_timeline.py` — takes a list of timestamped events and drafts them into a narrative
- `investigation_agent.py` — takes a structured alert (alert type, entity, a list of risk signals) and produces a triage summary plus one recommended next investigative step, never a verdict

This isn't automation replacing a human, it's a triage aid. Important distinction and I built the prompts around enforcing it.

**Cost, honestly**
Everything else in this portfolio (Wazuh, TheHive, LocalStack, Terraform) is genuinely free. This isn't — API calls cost a small amount per token. Not going to pretend otherwise just because the rest of the lab is free. It's cheap to test with (fractions of a cent per call for something this small) but it's not zero.

**Running it**
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=<your key>

python3 alert_summarizer.py sample-wazuh-alert.json
python3 incident_timeline.py sample-events.json
python3 investigation_agent.py sample-structured-alert.json
```
The sample JSON files use made-up hostnames and the `198.51.100.0/24` range that's reserved specifically for documentation examples — nothing real in there, safe to run against.

**Why the prompts are written the way they are**
First draft of the summarizer prompt just said "summarize this alert." Turns out an LLM asked to summarize an alert will also happily hand you a verdict you didn't ask for — "this looks benign," "probably a false positive" — which is exactly the kind of thing a triage *aid* shouldn't be doing on its own. Had to explicitly tell it not to decide anything or recommend an action. Same idea in the timeline script — it's forced to end every output with an "UNVERIFIED DRAFT, human review required" line so nobody downstream mistakes a first-pass narrative for something validated.

Small thing, but it's the actual design decision here. The API call itself is maybe five lines.

`investigation_agent.py` uses the same discipline, one step further: its system prompt explicitly rules out containment/remediation actions too, not just a verdict, because "recommend a next step" is a more open door than "summarize this" and I'd rather close that off in the prompt than find out the model walked through it.

**Concept: what a real pipeline version of this would look like**

These three scripts each call the Claude API directly against a JSON file sitting on disk. A real deployment of this idea would not look like that, it would look something like:

```
Sentinel (raw alerts, sign-in/audit logs)
        |
        v
Data lake (retained, queryable history, not just the live alert queue)
        |
        v
Security Copilot (pulls the relevant slice of that history into context
for a given investigation)
        |
        v
An AI agent, e.g. built on Azure AI Foundry (wraps a model call with the
same "triage aid, summarize and suggest a next step, never decide" prompt
discipline these scripts use, but wired into real data instead of a JSON
file, and into a real analyst workflow instead of a CLI)
```

I'm not building that pipeline here, on purpose. Wiring up Sentinel, a data lake, Copilot, and an AI Foundry agent for real would mean exposing real environment details (tenant structure, actual data lake schema, actual Copilot plugin config) that don't belong in a public portfolio repo, and building a fake version of all four hops just to have something to point a diagram at would be a lot of scaffolding for not much signal. `investigation_agent.py` is the part of that pipeline that's actually interesting to demonstrate, the triage-summary skill itself, in standalone form: same input shape (a structured alert), same prompting discipline, same guardrail against rendering a verdict, just without the four hops of infrastructure in front of it.

Don't commit `ANTHROPIC_API_KEY`. `venv/` is gitignored.

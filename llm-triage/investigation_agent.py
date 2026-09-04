#!/usr/bin/env python3
"""Take a structured alert (alert type, entity, a list of risk signals) and
produce a triage summary plus one recommended next investigative step.

This is a standalone stand-in for a real pipeline shape (Sentinel -> a data
lake -> Security Copilot -> an AI Foundry agent), demonstrating the same
triage-summary skill in isolation, without wiring up any of that real
infrastructure. See the "Concept: what a real pipeline version of this
would look like" section in README.md for the genericized architecture
this is standing in for.

Same guardrail discipline as alert_summarizer.py: this never renders a
verdict ("this is malicious," "this is a false positive") and never
recommends an action beyond the single next investigative step it is
asked for. It is a triage aid, not an automated responder or a decision-
maker — see README.md's "Why the prompts are written the way they are"
for the mistake that discipline was written in response to.

Usage:
    export ANTHROPIC_API_KEY=<your key>   # never commit this
    python3 investigation_agent.py sample-structured-alert.json
"""
import json
import sys

import anthropic

SYSTEM_PROMPT = (
    "You are a SOC triage assistant. Given a structured security alert as "
    "JSON (an alert type, an entity, a list of risk signals, and optional "
    "context), produce exactly two things: (1) a plain-English triage "
    "summary of what the alert is describing, in a few sentences an "
    "analyst can read in under 10 seconds, and (2) one concrete "
    "recommended next investigative step, labelled 'Next step:'. Do not "
    "invent risk signals, entities, or context fields that are not in the "
    "input. Do not render a verdict on whether this is malicious, "
    "benign, or a false positive, and do not recommend containment or "
    "remediation actions (isolating a host, disabling an account, and "
    "similar) — only an investigative step, something that gathers more "
    "information rather than takes action. You are a triage aid, not an "
    "automated responder and not a decision-maker."
)


def investigate(alert: dict) -> str:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=400,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(alert, indent=2)}],
    )
    return response.content[0].text


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <structured-alert.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        alert = json.load(f)

    print(investigate(alert))

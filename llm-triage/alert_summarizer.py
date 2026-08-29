#!/usr/bin/env python3
"""Summarize a raw alert JSON blob into a 5-second analyst-readable summary.

Usage:
    export ANTHROPIC_API_KEY=<your key>   # never commit this
    python3 alert_summarizer.py sample-wazuh-alert.json
"""
import json
import sys

import anthropic

SYSTEM_PROMPT = (
    "You are a SOC triage assistant. Given a raw security alert as JSON, "
    "produce a plain-English summary a Tier 1 analyst can read in under 5 "
    "seconds: what happened, on what host/account, how severe, and the one "
    "most useful next step. Do not invent fields that aren't in the alert. "
    "Do not decide the alert is a false positive or take any action — you "
    "are a triage aid, not an automated responder."
)


def summarize(alert: dict) -> str:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(alert, indent=2)}],
    )
    return response.content[0].text


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <alert.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        alert = json.load(f)

    print(summarize(alert))

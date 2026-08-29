#!/usr/bin/env python3
"""Draft a readable incident timeline from a list of timestamped log entries.

The output is a first-draft narrative for a human analyst to review and
correct — it is never treated as a validated record of what happened.

Usage:
    export ANTHROPIC_API_KEY=<your key>   # never commit this
    python3 incident_timeline.py sample-events.json
"""
import json
import sys

import anthropic

SYSTEM_PROMPT = (
    "You are drafting an incident timeline for a human analyst to review. "
    "Given a list of timestamped log/alert entries (JSON), produce a "
    "chronological narrative connecting them into a plausible sequence of "
    "attacker (or benign) activity. Use only what's in the data — do not "
    "invent timestamps, hosts, or actions not present in the input. End "
    "with a clearly labelled 'UNVERIFIED DRAFT — human review required' "
    "line; this is a drafting aid, not a validated incident record."
)


def build_timeline(events: list) -> str:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=800,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(events, indent=2)}],
    )
    return response.content[0].text


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <events.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        events = json.load(f)

    print(build_timeline(events))

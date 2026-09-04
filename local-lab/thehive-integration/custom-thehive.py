#!/usr/bin/env python3
"""Wazuh custom integration -> TheHive.
Called by Wazuh's integrator (wazuh-integratord) whenever a matching alert
fires. Creates a real TheHive case from the alert so the SIEM-to-case-
management gap this lab has had since day one actually closes.

Wazuh calls integration scripts as: script.py <alert_file> <api_key> [options]
The alert JSON is passed as a file path (argv[1]); the API key comes from
argv[2], sourced from the <api_key> tag in the <integration> block in
ossec.conf — never hardcoded here, so this script is safe to commit.

Stdlib only (urllib, not requests) — the Wazuh manager container's Python
doesn't have third-party packages installed, and adding them would be
fragile across container recreation.
"""
import sys
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

THEHIVE_URL = "http://host.docker.internal:9000"

SEVERITY_RANGES = [
    (range(0, 4), 1),    # low
    (range(4, 7), 2),    # medium
    (range(7, 12), 3),   # high
    (range(12, 16), 4),  # critical
]


def level_to_severity(level):
    for r, sev in SEVERITY_RANGES:
        if level in r:
            return sev
    return 2


def main():
    alert_file = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    if not api_key:
        raise RuntimeError("no API key passed — check the <api_key> tag in the <integration> block")

    with open(alert_file) as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    title = f"Wazuh alert: {rule.get('description', 'unknown')}"
    level = rule.get("level", 0)

    description_lines = [
        f"Rule ID: {rule.get('id')}",
        f"Level: {level}",
        f"Groups: {', '.join(rule.get('groups', []))}",
        f"Location: {alert.get('location', 'n/a')}",
        f"Timestamp: {alert.get('timestamp', datetime.now(timezone.utc).isoformat())}",
        "",
        "Full alert:",
        "```",
        json.dumps(alert, indent=2)[:3000],
        "```",
    ]

    case = {
        "title": title,
        "description": "\n".join(description_lines),
        "severity": level_to_severity(level),
        "tlp": 2,
        "pap": 2,
        "tags": ["wazuh", "auto-created"] + rule.get("groups", []),
        "source": "wazuh-integration",
    }

    body = json.dumps(case).encode("utf-8")
    req = urllib.request.Request(
        f"{THEHIVE_URL}/api/v1/case",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        print(f"created case: {result.get('_id')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"custom-thehive.py error: {e}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Polls Auth0's Management API System Log for new events and appends
them to a file Wazuh watches, same on-demand-relay pattern as the
Cloudflare/MySQL sources. Auth0's log API is checkpoint-based (each
entry has a `log_id`, and `?from=<log_id>` returns only entries after
it) so this naturally avoids re-forwarding the same event twice across
runs, unlike the file-tailing relays which need to start mid-file.

Credentials come from environment variables, never hardcoded:
    export AUTH0_DOMAIN=your-tenant.us.auth0.com
    export AUTH0_CLIENT_ID=...
    export AUTH0_CLIENT_SECRET=...
    python3 poll_auth0_logs.py
"""
import os
import sys
import json
import time
import urllib.request
import urllib.parse

DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["AUTH0_CLIENT_ID"]
CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]
OUT_PATH = os.environ.get("OUT_PATH", os.path.expanduser("~/securitylab/auth0-lab/wazuh-feed/auth0-events.log"))
CHECKPOINT_PATH = os.path.expanduser("~/securitylab/auth0-lab/last_log_id.txt")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))


def get_token():
    body = json.dumps({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": f"https://{DOMAIN}/api/v2/",
        "grant_type": "client_credentials",
    }).encode()
    req = urllib.request.Request(
        f"https://{DOMAIN}/oauth/token", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def fetch_logs(token, from_id=None):
    params = {"per_page": "50", "sort": "date:1"}
    if from_id:
        params["from"] = from_id
        params["take"] = "50"
    else:
        params["page"] = "0"
    url = f"https://{DOMAIN}/api/v2/logs?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def load_checkpoint():
    if os.path.exists(CHECKPOINT_PATH):
        return open(CHECKPOINT_PATH).read().strip() or None
    return None


def save_checkpoint(log_id):
    os.makedirs(os.path.dirname(CHECKPOINT_PATH), exist_ok=True)
    with open(CHECKPOINT_PATH, "w") as f:
        f.write(log_id)


def main():
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    last_id = load_checkpoint()
    token = get_token()
    token_fetched_at = time.time()

    print(f"polling {DOMAIN}, starting from log_id={last_id or '(beginning)'}", file=sys.stderr)

    with open(OUT_PATH, "a", buffering=1) as out:
        while True:
            if time.time() - token_fetched_at > 3000:  # refresh before 1hr expiry
                token = get_token()
                token_fetched_at = time.time()

            try:
                entries = fetch_logs(token, from_id=last_id)
            except urllib.error.HTTPError as e:
                print(f"fetch error: {e}", file=sys.stderr)
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            for entry in entries:
                out.write(json.dumps(entry) + "\n")
                last_id = entry["log_id"]
                print(f"forwarded: {entry.get('type')} - {entry.get('description', '')[:60]}", file=sys.stderr)

            if entries:
                save_checkpoint(last_id)

            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()

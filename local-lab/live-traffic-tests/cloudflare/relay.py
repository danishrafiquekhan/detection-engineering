#!/usr/bin/env python3
"""Reads pretty-printed JSON objects (one per Worker invocation) from
`wrangler pages deployment tail --format=json` on stdin, pulls out
cf_lab_request log entries, and appends each as a single JSON line to
the file Wazuh's manager is watching via localfile.

Run this on demand, pointed at the live tail of a specific deployment
(the deployment ID changes on every redeploy, so this has to be
restarted against the new ID each time you redeploy the site):

    npx wrangler pages deployment tail <deployment-id> \
        --project-name=<project> --format=json | python3 relay.py
"""
import sys
import json

OUT_PATH = "/var/log/cloudflare/access.log"  # bind-mounted into the Wazuh manager container


def extract_requests(buf):
    decoder = json.JSONDecoder()
    idx = 0
    length = len(buf)
    results = []
    while idx < length:
        while idx < length and buf[idx] in " \t\r\n":
            idx += 1
        if idx >= length:
            break
        try:
            obj, end = decoder.raw_decode(buf, idx)
        except json.JSONDecodeError:
            break
        results.append(obj)
        idx = end
    return results, buf[idx:]


def main():
    buf = ""
    with open(OUT_PATH, "a", buffering=1) as out:
        for chunk in sys.stdin:
            buf += chunk
            objects, buf = extract_requests(buf)
            for event in objects:
                for log_entry in event.get("logs") or []:
                    for msg in log_entry.get("message", []):
                        if not isinstance(msg, str):
                            continue
                        try:
                            parsed = json.loads(msg)
                        except json.JSONDecodeError:
                            continue
                        if "cf_lab_request" in parsed:
                            out.write(json.dumps(parsed["cf_lab_request"]) + "\n")
                            print("forwarded:", parsed["cf_lab_request"]["path"], file=sys.stderr)


if __name__ == "__main__":
    main()

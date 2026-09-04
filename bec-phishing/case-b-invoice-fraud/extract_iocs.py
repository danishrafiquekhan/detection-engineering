#!/usr/bin/env python3
"""Extract IOCs from a batch of email headers, for the invoice-fraud /
bulk-mail BEC pattern (see ../README.md for the case this supports).

Input is JSON, a list of parsed header objects (not raw RFC 822 text, this
mirrors how sample-logs/ elsewhere in this repo ships already-parsed JSON
rather than raw log lines, since the point is exercising the extraction
logic, not writing a MIME parser). Each row is expected to carry at least
MessageId, From, ReceivedFromDomain, ReceivedFromIp, and AuthenticationResults,
see sample-data/sample-email-headers.json for the exact shape.

Output is a structured IOC list: one entry per row with the sending IP, the
message ID, and the sending domain pulled out, plus a rollup of how many
messages shared each (ip, domain) pair, which is the actual "high volume"
signal this case is about. This does not decide anything is malicious, it
is IOC extraction, not a verdict, deliberately kept separate from any
"is this BEC" judgment, that call is the analyst's, using this alongside
the Sigma rule's other conditions (recipient, subject theme).

Usage:
    python3 extract_iocs.py sample-data/sample-email-headers.json
    python3 extract_iocs.py sample-data/sample-email-headers.json --out iocs.json
    python3 extract_iocs.py sample-data/sample-email-headers.json --format csv
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

FROM_ADDRESS_RE = re.compile(r'<([^<>]+)>')


def extract_domain(email_address: str) -> str:
    return email_address.rsplit("@", 1)[-1].lower() if "@" in email_address else ""


def extract_from_address(from_header: str) -> str:
    match = FROM_ADDRESS_RE.search(from_header)
    return match.group(1) if match else from_header.strip()


def extract_iocs(rows: list) -> dict:
    entries = []
    volume = defaultdict(int)

    for row in rows:
        from_address = extract_from_address(row.get("From", ""))
        sender_domain = extract_domain(from_address)
        bulk_infra_domain = row.get("ReceivedFromDomain", "")
        sender_ip = row.get("ReceivedFromIp", "")

        entry = {
            "message_id": row.get("MessageId", ""),
            "sender_ip": sender_ip,
            "sender_display_address": from_address,
            "sender_domain": sender_domain,
            "bulk_infra_domain": bulk_infra_domain,
            "recipient": row.get("To", ""),
            "subject": row.get("Subject", ""),
            "auth_results": row.get("AuthenticationResults", ""),
        }
        entries.append(entry)
        volume[(sender_ip, bulk_infra_domain)] += 1

    rollup = [
        {"sender_ip": ip, "bulk_infra_domain": domain, "message_count": count}
        for (ip, domain), count in sorted(volume.items(), key=lambda kv: -kv[1])
    ]

    return {"iocs": entries, "volume_by_sender": rollup}


def write_csv(entries: list, path: Path) -> None:
    fieldnames = [
        "message_id", "sender_ip", "sender_display_address", "sender_domain",
        "bulk_infra_domain", "recipient", "subject", "auth_results",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("headers_file", help="JSON file of parsed email headers")
    parser.add_argument("--out", help="write output here instead of stdout")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    args = parser.parse_args()

    with open(args.headers_file) as f:
        rows = json.load(f)

    result = extract_iocs(rows)

    if args.format == "csv":
        out_path = Path(args.out) if args.out else Path("iocs.csv")
        write_csv(result["iocs"], out_path)
        print(f"Wrote {len(result['iocs'])} IOC rows to {out_path}", file=sys.stderr)
        print("Note: --format csv only writes the per-message IOC rows, "
              "not the volume_by_sender rollup. Use --format json for that.",
              file=sys.stderr)
        return

    output = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(output + "\n")
        print(f"Wrote output to {args.out}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()

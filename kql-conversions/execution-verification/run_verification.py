#!/usr/bin/env python3
"""Runs every real .kql file in kql-conversions/generated/ against a local
Kusto emulator (kustainer) and prints real row counts and matched rows.

Requires kustainer already running and schema/data already loaded:
    docker run -d --name kustainer -e ACCEPT_EULA=Y -m 4G \
        -p 127.0.0.1:8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
    # then load setup_schema.kql and synthetic_data.kql statement-by-statement
    # against http://127.0.0.1:8080/v1/rest/mgmt (see README.md)

Stdlib only, same convention as the other relay/verification scripts in
this lab.
"""
import glob
import json
import urllib.request

KUSTAINER_URL = "http://127.0.0.1:8080/v1/rest/query"
GENERATED_DIR = "../generated"


def run_query(csl, timeout=20):
    body = json.dumps({"db": "NetDefaultDB", "csl": csl}).encode()
    req = urllib.request.Request(
        KUSTAINER_URL, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            table = json.loads(resp.read())["Tables"][0]
        return "OK", table["Rows"]
    except urllib.error.HTTPError as e:
        return "ERROR", e.read().decode()[:600]


def main():
    for path in sorted(glob.glob(f"{GENERATED_DIR}/*.kql")):
        with open(path) as f:
            csl = "".join(l for l in f if not l.strip().startswith("//")).strip()
        name = path.split("/")[-1]
        status, result = run_query(csl)
        print(f"=== {name} : {status} ===")
        if status == "OK":
            print(f"  {len(result)} row(s) matched")
            for row in result[:6]:
                print("   ", row)
        else:
            print("  ", result)
        print()


if __name__ == "__main__":
    main()

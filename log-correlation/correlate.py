#!/usr/bin/env python3
"""Run the detection-engineering Sigma/KQL rules' actual logic against
synthetic sample logs, and report which rows each rule flags.

This is not a Sentinel workspace and it is not real traffic. It exists
because the rules in this repo have never run against real sign-in data,
so there was no way to know if the logic in each KQL file actually does
what its Sigma source claims. This script re-implements each rule's KQL
condition in plain Python against small hand-built JSON fixtures and
checks the result against an expected outcome recorded on each fixture
row, the same way a unit test checks a function against known input.

What this proves: the rule logic fires on the rows it should and stays
quiet on the rows it should not, given data shaped like the real schema.
What this does not prove: false-positive rates, performance at real
volume, or anything about a live tenant. Those still need a real
Sentinel workspace, same as the top-level README says.

Usage:
    python3 correlate.py
"""
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

SAMPLE_DIR = Path(__file__).parent / "sample-logs"


def load(name):
    with open(SAMPLE_DIR / name) as f:
        return json.load(f)


def parse_ts(row):
    return datetime.strptime(row["TimeGenerated"], "%Y-%m-%dT%H:%M:%SZ")


def ci_eq(a, b):
    """KQL's =~ and in~ are case-insensitive equality, unlike plain Python ==."""
    return str(a).lower() == str(b).lower()


def ci_contains(haystack, needle):
    """KQL's plain `contains` is case-insensitive by default (contains_cs is the
    case-sensitive variant). Every `contains` in these rules is the default form,
    so this is the correct comparison, not just Python's case-sensitive `in`.
    """
    return needle.lower() in str(haystack).lower()


# --- Rule logic, one function per sigma-rules/*.yml + kql-conversions/generated/*.kql pair ---

def rule_impossible_travel(signinlogs):
    """SigninLogs | where RiskEventTypes contains "unfamiliarFeatures" or "anonymizedIPAddress" """
    flagged = set()
    for row in signinlogs:
        risk_types = row.get("RiskEventTypes", [])
        if any(ci_contains(rt, "unfamiliarFeatures") or ci_contains(rt, "anonymizedIPAddress") for rt in risk_types):
            flagged.add(row["Id"])
    return flagged


def rule_password_spray(signinlogs, threshold=10, window_minutes=10):
    """SigninLogs | where ResultType in~ ("50053","50126")
    | summarize FailedAccounts = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 10m)
    | where FailedAccounts >= 10
    """
    fail_codes = {50053, 50126}
    buckets = defaultdict(lambda: {"accounts": set(), "row_ids": []})
    for row in signinlogs:
        if row.get("ResultType") not in fail_codes:
            continue
        ts = parse_ts(row)
        bucket_start = ts - timedelta(
            minutes=ts.minute % window_minutes,
            seconds=ts.second,
            microseconds=ts.microsecond,
        )
        key = (row["IPAddress"], bucket_start)
        buckets[key]["accounts"].add(row["UserPrincipalName"])
        buckets[key]["row_ids"].append(row["Id"])

    flagged = set()
    for key, bucket in buckets.items():
        if len(bucket["accounts"]) >= threshold:
            flagged.update(bucket["row_ids"])
    return flagged


def rule_suspicious_signin_velocity(signinlogs):
    """SigninLogs | where ResultType == 0

    As written, this only filters to successful sign-ins. It does not
    actually compare country or check a time window between two sign-ins
    for the same account, which is what the Sigma title and description
    claim ("two different countries within a short time window"). That
    gap is real, not a bug in this harness. It is flagged in this
    repo's README rather than quietly fixed here, since fixing detection
    logic is a decision for the rule's own file, not for a test script.
    """
    return {row["Id"] for row in signinlogs if row.get("ResultType") == 0}


def rule_privileged_role_assignment(auditlogs):
    """AuditLogs | where OperationName =~ "Add member to role"
    and (TargetResources contains "Global Administrator" or TargetResources contains "Privileged Role Administrator")
    """
    flagged = set()
    for row in auditlogs:
        if not ci_eq(row.get("OperationName", ""), "Add member to role"):
            continue
        targets = row.get("TargetResources", "")
        if ci_contains(targets, "Global Administrator") or ci_contains(targets, "Privileged Role Administrator"):
            flagged.add(row["Id"])
    return flagged


def rule_conditional_access_policy_tampering(auditlogs):
    """AuditLogs | where (OperationName in~ ("Update conditional access policy", "Update policy"))
    and (ModifiedProperties contains "\\"state\\":\\"disabled\\"" or ModifiedProperties contains "excludeUsers" or ModifiedProperties contains "excludeGroups")
    """
    ops = ["Update conditional access policy", "Update policy"]
    flagged = set()
    for row in auditlogs:
        if not any(ci_eq(row.get("OperationName", ""), op) for op in ops):
            continue
        props = row.get("ModifiedProperties", "")
        if ci_contains(props, '"state":"disabled"') or ci_contains(props, "excludeUsers") or ci_contains(props, "excludeGroups"):
            flagged.add(row["Id"])
    return flagged


def rule_suspicious_oauth_consent(auditlogs):
    """AuditLogs | where (OperationName =~ "Consent to application" and ResultType =~ "success")
    and (ModifiedProperties contains "Mail.ReadWrite" or "Mail.Send" or "Directory.ReadWrite.All" or "Files.ReadWrite.All")
    """
    high_risk_scopes = ["Mail.ReadWrite", "Mail.Send", "Directory.ReadWrite.All", "Files.ReadWrite.All"]
    flagged = set()
    for row in auditlogs:
        if not ci_eq(row.get("OperationName", ""), "Consent to application"):
            continue
        if not ci_eq(row.get("ResultType", ""), "success"):
            continue
        props = row.get("ModifiedProperties", "")
        if any(ci_contains(props, scope) for scope in high_risk_scopes):
            flagged.add(row["Id"])
    return flagged


def rule_mass_file_download(officeactivity):
    """OfficeActivity | where Operation =~ "FileDownloaded"

    No per-user threshold in the KQL, so this matches every download
    event, not just bulk ones. attack-mapping.csv already calls this
    "high FP risk by design", the fixtures below are built to show that
    honestly instead of hiding it behind a cherry-picked sample.
    """
    return {row["Id"] for row in officeactivity if ci_eq(row.get("Operation", ""), "FileDownloaded")}


def rule_suspicious_powershell_execution(deviceprocessevents):
    """imProcessCreate | where TargetProcessName endswith "\\powershell.exe"
    and (TargetProcessCommandLine contains "-enc" or "-EncodedCommand" or "-e " or "FromBase64String")
    """
    flags = ["-enc", "-EncodedCommand", "-e ", "FromBase64String"]
    flagged = set()
    for row in deviceprocessevents:
        image = row.get("TargetProcessName", "")
        if not image.lower().endswith("\\powershell.exe"):
            continue
        cmdline = row.get("TargetProcessCommandLine", "")
        if any(ci_contains(cmdline, flag) for flag in flags):
            flagged.add(row["Id"])
    return flagged


RULES = [
    {
        "name": "impossible-travel",
        "technique": "T1078.004",
        "source": "signinlogs.json",
        "run": rule_impossible_travel,
    },
    {
        "name": "password-spray",
        "technique": "T1110.003",
        "source": "signinlogs.json",
        "run": rule_password_spray,
    },
    {
        "name": "suspicious-signin-velocity",
        "technique": "T1078.004",
        "source": "signinlogs.json",
        "run": rule_suspicious_signin_velocity,
    },
    {
        "name": "privileged-role-assignment",
        "technique": "T1098.003",
        "source": "auditlogs.json",
        "run": rule_privileged_role_assignment,
    },
    {
        "name": "conditional-access-policy-tampering",
        "technique": "T1556.009",
        "source": "auditlogs.json",
        "run": rule_conditional_access_policy_tampering,
    },
    {
        "name": "suspicious-oauth-consent",
        "technique": "T1528",
        "source": "auditlogs.json",
        "run": rule_suspicious_oauth_consent,
    },
    {
        "name": "mass-file-download",
        "technique": "T1567",
        "source": "officeactivity.json",
        "run": rule_mass_file_download,
    },
    {
        "name": "suspicious-powershell-execution",
        "technique": "T1059.001",
        "source": "deviceprocessevents.json",
        "run": rule_suspicious_powershell_execution,
    },
]


def main():
    sources = {}
    all_pass = True

    print("detection-engineering log correlation, synthetic fixtures only")
    print("=" * 72)

    for rule in RULES:
        source_name = rule["source"]
        if source_name not in sources:
            sources[source_name] = load(source_name)
        rows = sources[source_name]

        flagged = rule["run"](rows)

        expected_for_rule = [row for row in rows if row.get("_expectedRule") == rule["name"]]
        mismatches = []
        for row in expected_for_rule:
            actually_matched = row["Id"] in flagged
            if actually_matched != row["_expectedMatch"]:
                mismatches.append((row["Id"], row["_expectedMatch"], actually_matched))

        status = "PASS" if not mismatches else "FAIL"
        if mismatches:
            all_pass = False

        print(f"\n{rule['name']}  ({rule['technique']})  [{status}]")
        print(f"  source: {source_name}, rows flagged: {len(flagged)} of {len(rows)}")
        if flagged:
            print(f"  matched ids: {', '.join(sorted(flagged))}")
        if mismatches:
            for row_id, expected, actual in mismatches:
                print(f"  MISMATCH {row_id}: expected match={expected}, actual match={actual}")

    print("\n" + "=" * 72)
    print("ALL FIXTURES PASSED" if all_pass else "ONE OR MORE FIXTURES FAILED")
    print(
        "\nThis only checks rule logic against synthetic data shaped like the "
        "real schema. It does not validate false-positive rates or anything "
        "about a live tenant, see log-correlation/README.md."
    )
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

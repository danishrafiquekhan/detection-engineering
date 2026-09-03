**log-correlation**

A local test harness that runs the actual query logic from `sigma-rules/` and
`kql-conversions/generated/` against small, synthetic log files, and checks
whether each rule fires on the rows it should and stays quiet on the rows it
should not.

**Why this exists**

The top-level README already says it plainly: all 8 rules convert cleanly
and are syntactically valid, but none of them have run against real sign-in
data, so there was no way to know if the logic inside each KQL file actually
does what its Sigma source claims. Getting a real Sentinel workspace is still
the next real milestone, and this does not replace that. What it does is
close a smaller, immediate gap: it lets the rule logic itself get exercised
today, against data shaped like the real schema, instead of waiting on a
tenant signup to find out if a rule has an obvious bug in it.

It already found one. See "What this caught" below.

**What is in here**

- `correlate.py`: reads each sample log file, re-implements the matching
  rule's KQL condition in plain Python, and reports which rows it flags
- `sample-logs/`: four small JSON files (`signinlogs.json`, `auditlogs.json`,
  `officeactivity.json`, `deviceprocessevents.json`), one per Sentinel table
  the rules query, built by hand to exercise all 8 rules

Every row in `sample-logs/` carries an `_expectedRule`, `_expectedMatch`, and
usually a `_note` field. Those three are test metadata, not real log fields,
and `correlate.py` uses them to self-check: it runs each rule, then compares
what actually matched against what the fixture says should have matched, and
reports PASS or FAIL per rule.

**Running it**

```bash
python3 correlate.py
```

No dependencies beyond the standard library. Exit code is 0 if every fixture
matches its expected outcome, 1 otherwise.

**What this proves, and what it does not**

This proves the rule logic fires on the kind of row it is supposed to and
ignores the kind of row it is not, given data shaped like the real schema.

This does not prove false-positive rates against real traffic, performance
at real volume, or anything about how these rules behave against an actual
tenant. Two of the fixtures below are built specifically to demonstrate that
distinction rather than hide it.

**What this caught**

Building the `auditlogs.json` fixtures surfaced a real gap in
`conditional-access-policy-tampering`. The rule's KQL checks for the literal
text `"state":"disabled"` inside `ModifiedProperties`. Microsoft's actual
audit log format stores modified properties as an array of
`{displayName, oldValue, newValue}` objects, so a real policy-disabled event
would show up as something like `{"displayName":"State","oldValue":"\"enabled\"","newValue":"\"disabled\""}`,
never as the flattened `"state":"disabled"` the rule is looking for.

`sample-logs/auditlogs.json` has three rows that make this concrete:

- `aud-004`: a policy genuinely disabled, in the realistic Microsoft shape.
  The rule does not fire on it. This is the gap.
- `aud-004b`: the same event, written in the flattened shape the rule's
  condition was actually written to match. The rule fires. This confirms
  the substring check itself works, it is just checking for a shape that
  does not match real data.
- `aud-005`: a different tampering technique, adding an account to a
  policy's exclusion list. The rule's `excludeUsers` check happens to match
  this one even in the realistic shape, since it is a plain substring check
  rather than a key-specific one.

This is not fixed in `correlate.py`, on purpose. Fixing detection logic is a
decision that belongs in `sigma-rules/conditional-access-policy-tampering.yml`
and its generated KQL, not in a test script that is supposed to be checking
that file, not rewriting it. Recorded here so it does not get lost, and
because exact ModifiedProperties formatting still needs confirming against a
real tenant capture rather than assumed from documentation alone.

**suspicious-signin-velocity, a known-noisy rule by design**

The Sigma title claims impossible-travel style detection (two countries in a
short window), but the rule's actual condition is just `ResultType == 0`,
every successful sign-in. `sample-logs/signinlogs.json` includes two entirely
ordinary successful sign-ins (`sil-016`, `sil-017`) specifically to show the
rule matching everyday traffic, not an attack. Same situation as
`mass-file-download`, already documented as high false-positive risk by
design in `attack-mapping.csv`, this is the sign-in equivalent of that same
honest gap.

**A note on the synthetic data**

Every IP address in these fixtures is from a documentation-reserved range
(`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`, per RFC 5737), the same
convention already used in `llm-triage/`. Usernames, tenant name, hostnames,
and file names are all made up. Nothing in `sample-logs/` is real data or
modeled on a real incident.

**identity-incident-response**

Two full identity-incident case studies, MFA fatigue and impossible
travel, taken all the way through the lifecycle: detection, incident
report, response playbook, and a proactive hunting query. `sigma-rules/`
at the repo root is just the detection logic, one Sigma rule and its
converted KQL, nothing else. This folder is what sits around a detection
once it actually fires: what an analyst would see, how they would triage
and investigate it, what a response automation would ideally do, and what
a hunt looks like for the version of the pattern the alert itself might
miss. Same relationship as `guid-triage/` and `bec-phishing/` have to
`sigma-rules/`, a case folder with its own supporting artifacts, not part
of the tracked 8-rule `make convert` pipeline.

**What is in here**

- `mfa-fatigue/`: nothing for this existed anywhere in the repo before.
  Built from scratch: a Sigma rule for the push-bombing pattern
  (`mfa-fatigue-detection.yml`), hand-written KQL with the aggregation
  the rule alone cannot express (`mfa-fatigue-detection.kql`, same gap as
  `password-spray.yml`), a fictional Contoso incident report, a response
  playbook, and a proactive hunting query
- `impossible-travel/`: builds on the rule that already exists at
  `sigma-rules/impossible-travel.yml` and
  `kql-conversions/generated/impossible-travel.kql`. Does not duplicate
  either. Adds the incident report, the response playbook, and a hunting
  query that deliberately does its own geo-velocity math instead of
  leaning on the same `RiskEventTypes` signal the alerting rule already
  depends on, see that folder's `hunting-query.kql` for why that
  independence matters

**Why `mfa-fatigue-detection` also has a row in the root `attack-mapping.csv`**

It is the one rule in this folder that did not already exist somewhere
else in the repo, so unlike the impossible-travel case (whose underlying
rule is already tracked), this is a genuinely new detection. It lives here
rather than in `sigma-rules/` because this folder is the right home for a
rule built alongside its full case study, not because it is any less real
than the eight rules in the tracked pipeline. It is not part of
`make convert`'s glob and will not appear if you run that target; the
`.kql` file next to it was written by hand to match the same style,
same convention as `guid-triage/guid-identity-check.kql`.

**The playbooks in both subfolders**

Both `playbook.md` files are response designs, not deployed automations.
There is no Sentinel workspace behind this repo (see the root README's
"Honest state of things"), so nothing described as an "automated action"
in either playbook has actually run. They are written to the level of
detail I would want settled before opening the Logic App designer, not as
a record of something already built.

**A note on the fictional data**

Contoso, every user (`j.reyes@contoso.com`, `d.oyelaran@contoso.com`,
`m.oduya@contoso.com`), every IP address (drawn from the RFC 5737
documentation ranges, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), the
lookalike domain (`contoso-finance.net`), and the fictional OAuth app
client ID in `mfa-fatigue/incident-report.md` are made up for this case
study. Nothing in this folder is modeled on a real incident or a real
organization.

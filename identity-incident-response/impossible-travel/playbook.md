**Impossible travel response playbook — design, not deployed**

This is a design for a Sentinel automation rule / Logic App playbook, not
something running against a real tenant. There is no Sentinel workspace
behind this repo, so nothing below has actually been built or exercised
against live data. Treat this as the spec I would build from, not a
description of an existing automation.

**Purpose**

Get a flagged impossible-travel session killed before it is used for
anything, and get the investigation started with the right question
already asked: was this a guessed password, or a stolen/replayed token.
The `incident-report.md` case in this folder shows why that distinction
matters early, the response for each is different, and the playbook design
below tries to make sure that check happens automatically instead of
depending on an analyst remembering to look for it.

**Trigger**

- Detection: `sigma-rules/impossible-travel.yml` /
  `kql-conversions/generated/impossible-travel.kql`, firing on
  `RiskEventTypes` containing `unfamiliarFeatures` or
  `anonymizedIPAddress`
- No additional threshold beyond what the existing rule already applies;
  this playbook is the response layer for that rule as-is, not a
  redefinition of when it fires

**Automated Actions**

1. Pull the immediately preceding sign-in event for the same account (the
   "before" half of the impossible pair) and attach both events to the
   case automatically, so the analyst opens the case already looking at
   the comparison instead of having to go query for it first.
2. Check and record whether the flagged sign-in was interactive (fresh
   MFA challenge) or used an existing refresh token, and tag the case
   accordingly. This is the single most useful automated enrichment for
   this specific alert type, since it points the human investigation
   toward "credential compromise" or "token theft" from the start, per
   the incident report in this folder.
3. Revoke the account's active sessions and refresh tokens automatically
   when the flagged sign-in used a refresh token (the higher-confidence
   case for actual compromise, since it bypassed a fresh MFA challenge).
   For a fresh interactive sign-in that still tripped this rule, route to
   a human instead of auto-revoking, since a legitimate user who just
   traveled and used a new device/VPN can look identical to this signal on
   a single event.
4. Post the case, both sign-in events, and the interactive-vs-token
   determination to the SOC incident channel, tagged by which branch above
   it took.

**Manual Analyst Actions**

- Confirm with the user whether they were traveling, using a VPN, or
  otherwise have a legitimate explanation for the second location
- If session/token theft is suspected (the automated branch above), start
  looking for the theft mechanism: recent phishing reports, endpoint
  alerts, unusual OAuth consents, per the incident report's Investigation
  Steps, since revoking the cloud session does not fix a compromised
  endpoint
- Review what the flagged session actually accessed before it was caught,
  and expand the case if it touched anything sensitive
- Decide on password reset, MFA re-registration, and device compliance
  requirements before re-enabling the account, and document the actual
  root cause once known (guessed credential vs. stolen token) since that
  determines whether other accounts need the same check

**Notes**

- The interactive-vs-token branch above is the main design decision in
  this playbook and the part I am least confident about without real
  traffic: auto-revoking every flagged sign-in regardless of that
  distinction would be simpler to build but would also auto-revoke
  legitimate travelers more often, and the interactive-sign-in branch is
  exactly the case that is most likely to be a false positive in the
  first place, a real trip, a real new device.
- This playbook is entirely dependent on `impossible-travel.yml`'s own
  dependency on Azure AD Identity Protection's risk classification (see
  that incident report's Lessons Learned). If Identity Protection does not
  flag something, this playbook never triggers on it, which is a real
  coverage gap, not something this response design fixes.
- Same standing caveat as the rest of this repo: none of "Automated
  Actions" above has run in a real Sentinel workspace. This is a playbook
  design, not a built and tested automation.

**Impossible travel incident report — Contoso**

Fictional case study, built on the detection logic already in
`sigma-rules/impossible-travel.yml` and its generated
`kql-conversions/generated/impossible-travel.kql`, not a new rule. Contoso
is a made-up org; every user, IP, device ID, and timestamp below is
invented. IPs are drawn from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), same convention as the
rest of this repo.

**Summary**

On 2026-08-30, `m.oduya@contoso.com` (a Contoso sales engineer based in
Chicago) signed in successfully from `198.51.100.12` at 09:04 UTC, a
device and IP consistent with her normal working pattern. At 09:41 UTC,
thirty-seven minutes later, a second successful sign-in occurred on the
same account from `192.0.2.201`, an address Azure AD Identity Protection's
own scoring flagged with `RiskEventTypes` containing both
`unfamiliarFeatures` and `anonymizedIPAddress`, which is exactly the
condition `impossible-travel.yml` fires on. `192.0.2.201` resolved (in
this fictional scenario) to a commercial VPN exit node with no
geographic or device history against this account. No physical route puts
the same person on a laptop in Chicago at 09:04 and behind an anonymizing
VPN exit node thirty-seven minutes later; either the credential was reused
from a second location, or a session/token was replayed from
infrastructure the real user was never on.

The 09:41 sign-in used a refresh token, not a fresh password entry
(`AuthenticationRequirement` showed no interactive MFA challenge on the
second event), which matters for the investigation below: this looks less
like "someone guessed her password from another country" and more like a
stolen or replayed session token, since a password-based sign-in from a
genuinely new location and device would normally re-trigger MFA under
Contoso's Conditional Access policy, and this one did not.

**Detection Source**

- Detection: `sigma-rules/impossible-travel.yml` (existing rule, not
  duplicated here), converted KQL at
  `kql-conversions/generated/impossible-travel.kql`
- Data Source: Azure AD Sign-in Logs (`SigninLogs`), specifically the
  `RiskEventTypes` field populated by Azure AD Identity Protection
- Technique: T1078.004 (Valid Accounts: Cloud Accounts)
- Same caveat as everywhere else in this repo: this rule has not run
  against a real Sentinel workspace. It relies entirely on Identity
  Protection's own risk classification already being correct and already
  present in the log row, which is a real dependency worth stating
  plainly, not a gap I have tested around.

**Triage Steps**

1. Pull both sign-in events for the account and lay them side by side:
   timestamp, IP, device ID, `RiskEventTypes`, and whether the sign-in was
   interactive (fresh credential + MFA) or used an existing token. The
   time delta here, 37 minutes between Chicago and an anonymized VPN
   node, is the first thing to sanity-check against any known geography;
   thirty-seven minutes is not enough time to travel between those two
   points by any legitimate means.
2. Check whether the flagged sign-in used a refresh token versus a full
   interactive challenge. In this case it did not re-trigger MFA, which
   shifts the likely root cause from "password compromise" toward "token
   theft or session replay," and changes what containment actually needs
   to accomplish (killing the session, not just resetting a password).
3. Confirm the account did not have any legitimate reason to be behind a
   VPN at that time (a documented corporate VPN egress range would explain
   `anonymizedIPAddress` without being an incident; Contoso does not
   provision that range in this scenario, so it does not apply here, but
   it is the first thing to rule out before treating every VPN sign-in as
   hostile).

**Evidence to Collect**

- Both sign-in events in full, plus any other sign-ins on the account in
  the surrounding 24 hours
- Device ID, browser/OS fingerprint, and whether the flagged sign-in's
  device has ever been seen on this account before
- `AuditLogs` entries following the flagged sign-in: mailbox rule changes,
  app consents, MFA method registrations, Conditional Access exclusions
- Confirmation from the user: were they traveling, using a personal VPN,
  or aware of any sign-in from an unexpected location around that time

**Investigation Steps**

1. Rule out the mundane explanations first: a corporate VPN client that
   exits through a third-party provider, a mobile carrier that assigns
   IPs shared across a wide region, or the user legitimately using a
   privacy VPN for unrelated reasons. In this scenario, Contoso has no
   corporate VPN that routes through `192.0.2.201`'s provider and the user
   denies using a personal VPN, which removes both.
2. Given the refresh-token detail from Triage Step 2, focus the
   investigation on how a valid session could have left the user's actual
   device: a prior phishing page that harvested a token (an adversary-
   in-the-middle kit), malware with session-cookie theft capability, or a
   synced browser profile with saved session state on an unmanaged
   device. Each of these has different remediation, which is why nailing
   down the mechanism matters, not just the fact of the anomaly.
3. Check what the second session actually did before it was noticed:
   mailbox access, file downloads, app consents. In this scenario the
   session was used to browse two SharePoint sites the user normally
   accesses, but made no changes, which argues for reconnaissance rather
   than immediate exfiltration or persistence, though that read could
   change if evidence surfaces later.
4. Check whether this account's risk score or sign-in pattern shows any
   earlier anomaly that was missed, since token theft usually has an
   earlier point of compromise (a phishing click, a malicious OAuth
   consent) that predates the sign-in this rule actually caught.

**Containment Actions**

- Revoke all active sessions and refresh tokens on the account
  immediately; a password reset alone does not address a stolen token
- Force MFA re-registration and, if available, require a fresh interactive
  sign-in with Conditional Access device compliance enforced before the
  account is usable again
- Block the flagged IP/VPN egress range at the Conditional Access layer
  pending investigation, understanding this is a minor speed bump against
  an attacker who can rotate exit nodes
- If a phishing or malware vector is suspected as the token's origin,
  isolate the user's actual endpoint pending a forensic look, since
  clearing the cloud session does not clean up a compromised device

**Remediation Steps**

- If the investigation points to an adversary-in-the-middle phishing kit,
  review recent inbound mail and any reported phishing from around the
  likely compromise window, and check whether other users received the
  same lure
- Move the account (and ideally the broader org) toward Conditional Access
  policies that bind tokens to a specific device/location signal, since
  the whole reason this stolen-token pattern works is that a bare refresh
  token is portable to any device or IP by default
- Shorten token/session lifetimes for higher-risk roles if platform
  licensing allows it, which reduces the usable window for a stolen token
  even when theft is not caught immediately
- Re-check whether Identity Protection's risk-based Conditional Access
  policy (auto-block or auto-MFA-challenge on `atRisk` sign-ins) was
  actually enabled and enforcing, versus just reporting, since this
  incident's fix is only as good as whether the platform acts on the same
  signal this Sigma rule is reading after the fact

**Lessons Learned**

- `impossible-travel.yml` as written depends entirely on Azure AD Identity
  Protection having already classified the sign-in correctly. That is a
  real strength (someone else's threat-intel and geo-velocity modeling,
  not mine, doing the hard classification work) and a real weakness (if
  Identity Protection does not flag a genuinely impossible pair of
  sign-ins, this rule sees nothing; it is not doing its own geo-velocity
  math). The hunting query in this folder exists specifically to cover
  that gap with an independent, rule-agnostic calculation.
- The refresh-token detail in this scenario is the actual lesson: not
  every impossible-travel case is a guessed password, and treating all of
  them as "reset the password and move on" would have missed the token-
  theft root cause here. Triage needs to check whether MFA re-triggered,
  not just whether the location changed.
- Same standing caveat as the rest of this repo: none of this has been
  validated against real sign-in data or a real Identity Protection risk
  feed. The rule compiles and the investigation steps are grounded in how
  the fields actually behave, but "will this fire cleanly and not drown in
  false positives on real traffic" is still an open question.

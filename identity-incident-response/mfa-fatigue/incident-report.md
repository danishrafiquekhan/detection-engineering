**MFA fatigue incident report — Contoso**

Fictional case study. Contoso is a made-up org, every user, IP address,
device ID, and timestamp below is invented for this write-up. IPs are drawn
from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), same convention as the rest of this repo. Nothing here is
modeled on a real incident.

**Summary**

On 2026-09-02 between 02:11 and 02:19 UTC, an external actor with a valid
password for `j.reyes@contoso.com` (a Contoso finance analyst) triggered 14
consecutive Microsoft Authenticator push notifications to her phone. She
declined the first several, assumed it was a stale session or a glitch, and
approved the 13th push at 02:18 UTC without reading the sign-in details
first. The sign-in completed from `203.0.113.44`, an IP with no prior
history against this account, geolocated well outside any location Reyes
had signed in from before. Within four minutes of the successful sign-in,
the session was used to register a new OAuth application
(`Contoso Sync Helper`, client ID `f1a2b3c4-5d6e-4f70-8a1b-2c3d4e5f6a7b`,
fictional) with `Mail.Read` and `Mail.Send` delegated scope, and to create
an inbox rule on Reyes's mailbox that silently forwarded messages
containing the words "invoice" and "wire" to an external address at
`billing-support@contoso-finance.net` (a lookalike domain, not the real
`contoso.com`).

Where the password came from is unknown and, for a fictional case, does
not need a specific origin. The realistic assumption is a prior unrelated
credential-stuffing list, a password that was reused, or a separate
phishing hit that was never in scope for this specific detection. This
write-up starts from "the attacker already has a valid password," because
that is the actual precondition for an MFA fatigue attack. If they did not
have the password, hammering the push button would not have gotten this
far.

**Detection Source**

- Detection: `mfa-fatigue-detection.yml` (`identity-incident-response/mfa-fatigue/`)
- Data Source: Azure AD Sign-in Logs (`SigninLogs`)
- Techniques: T1621 (Multi-Factor Authentication Request Generation), T1110 (Brute Force)
- As with every rule in this repo, this one has not run against a real Sentinel workspace. Everything below assumes the rule fires as designed; I have not validated that against live traffic.

**Triage Steps**

1. Pull the alert's `UserPrincipalName` and window (`FirstChallenge` /
   `LastChallenge` from the KQL's aggregation) and confirm the raw
   `ChallengeCount`. Fourteen denied/timed-out MFA prompts inside eight
   minutes for one account is not something a legitimate user produces by
   accident; a genuine fumble is one or two failures, not a double-digit
   burst.
2. Check whether the burst ends in a successful sign-in (`ResultType == 0`)
   for the same user shortly after the last challenge. If it does not, the
   attacker gave up or the user never caved. If it does, this stops being a
   "watch and see" alert and becomes an active-compromise investigation,
   which is what happened here (successful sign-in at 02:18 UTC, one minute
   after the burst's last recorded challenge).
3. Note the source IP and device on the successful sign-in versus the
   denied challenges. In this case all 14 challenges and the successful
   sign-in shared the same source IP, `203.0.113.44`, which rules out
   "different legitimate devices happening to overlap with an unrelated
   attack" and points to one actor running the whole thing from one
   session.

**Evidence to Collect**

- Full `SigninLogs` entries for the user across the burst window and the
  hour after it, not just the flagged events
- `AuditLogs` entries for the same window: OAuth app registrations or
  consent grants, inbox rule creation, mailbox permission changes, any
  Conditional Access policy or MFA method changes on the account
- The device/browser fingerprint on the successful sign-in versus the
  user's normal, previously-seen devices
- Confirmation from the user themselves: did they actually tap approve, and
  if so, do they remember what they were doing at that time (screen off,
  half asleep, in a meeting and reflexively approving to make it stop are
  all realistic answers, and all worth recording, not because they excuse
  it but because they inform the awareness follow-up)

**Investigation Steps**

1. Confirm the OAuth app grant and inbox rule found here are actually
   attacker-created and not a pre-existing legitimate integration that
   happens to look unfamiliar. In this case, `Contoso Sync Helper` had no
   corresponding change-ticket, no owner in the app registration's listed
   contacts, and was created four minutes after the compromised sign-in,
   which is enough to treat it as hostile pending further review, not
   proof on its own.
2. Check every account the same source IP (`203.0.113.44`) touched in the
   surrounding 24 hours. An MFA fatigue attempt against one user is rarely
   a one-off; the same actor commonly has a short list of accounts with
   already-known passwords and works down it. In this fictional scenario,
   the same IP also generated three MFA challenges (no approval) against a
   second Contoso account, `d.oyelaran@contoso.com`, roughly 40 minutes
   earlier, i.e., this user was likely tried first, failed, and the
   attacker moved on to Reyes.
3. Review the inbox rule's actual match criteria and where the forwarded
   mail was going. The forwarding target here, `billing-support@contoso-finance.net`,
   is a lookalike domain that was never legitimately used by Contoso
   finance, which both confirms hostile intent and gives an IOC to check
   against other mailboxes.
4. Check for downstream use of the `Mail.Send` scope the rogue OAuth app
   was granted, since read access to invoice-related mail plus send access
   is the combination that enables a follow-on BEC/invoice-fraud attempt
   (see `bec-phishing/case-b-invoice-fraud/` in this repo for what that
   next stage typically looks like from the recipient's side).

**Containment Actions**

- Revoke the user's active sessions and refresh tokens immediately
  (`Revoke-AzureADUserAllRefreshToken` or the equivalent Entra portal
  action), since the compromise happened at the session layer, not just
  the password
- Force a password reset on the account, on the assumption the password
  was already known to the attacker and simply reusing it is not sufficient
- Remove the rogue inbox rule and revoke consent for the rogue OAuth
  application (`Contoso Sync Helper`) before doing anything else that might
  tip the attacker off that they have been caught
- Block the source IP (`203.0.113.44`) at the tenant Conditional Access
  layer pending investigation, understanding that this is a speed bump, not
  a real control, since the attacker can move to a different IP for the
  next attempt

**Remediation Steps**

- Re-register the user's MFA methods from scratch rather than trusting the
  existing enrollment, since the device that approved the malicious push is
  the same device enrolled for legitimate MFA and there is no way to prove
  after the fact that it was not also compromised in some other way
- Enable number matching on Microsoft Authenticator so a bare "approve/
  deny" tap is no longer enough, the user has to read a number off the
  sign-in screen and type it into the app, which removes the reflexive-tap
  failure mode this incident actually exploited
- Apply a sign-in frequency / re-authentication Conditional Access policy
  and, where licensing allows, move higher-risk accounts to phishing-
  resistant MFA (FIDO2 security keys, Windows Hello for Business) instead
  of push-based MFA entirely
- Audit for other inbox rules and OAuth consents created tenant-wide in the
  same time window as this incident, in case this was not actually a
  single-account, single-actor event

**Lessons Learned**

- A push-based MFA burst is genuinely hard for a user to identify as an
  attack in the moment; it looks and feels like an app glitch, and "make it
  stop" is a completely human response. The fix belongs at the policy
  layer (number matching, rate-limiting push notifications, phishing-
  resistant MFA), not at "tell users to be more careful," which this
  incident's own timeline argues does not reliably work under fatigue.
- The detection rule as designed keys on `ResultType` values `500121` and
  `50074` plus a count threshold. I picked 5 challenges in a 10-minute
  window as the starting threshold; I have no real traffic to validate
  that against, so it is a guess informed by public examples of this
  attack pattern, not a tuned number. It would need real sign-in volume
  before I would trust it not to be too noisy or too quiet.
- Detecting the push burst is necessary but not sufficient. The real
  damage in this scenario happened after the successful sign-in (the OAuth
  grant and inbox rule), which argues for a second, complementary
  detection on unusual OAuth app registrations and inbox-rule creation
  immediately following a risky sign-in, something this rule alone does
  not cover and is not designed to cover.

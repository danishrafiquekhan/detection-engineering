**MFA fatigue response playbook — design, not deployed**

This is a design for a Sentinel automation rule / Logic App playbook, not
something running against a real tenant. I do not have a Sentinel
workspace with real sign-in traffic, so none of the "automated" steps
below have been built, tested, or run. Consider this the spec I would
implement first if I had a workspace to implement it against, written the
way I would want a playbook design documented before touching the Logic
App designer, not a claim that it exists anywhere yet.

**Purpose**

Cut the time between "attacker gets a user to approve a fatigue-driven MFA
push" and "attacker's session is dead" down from however long it takes a
human analyst to notice and act, to as close to the alert firing as
possible. The `incident-report.md` case in this folder is the reason this
matters: the actual damage (rogue OAuth app, mailbox forwarding rule)
happened in the four minutes right after the successful sign-in, a window
where automation has a real chance of beating a human to it and a human
usually does not.

**Trigger**

- Detection: `mfa-fatigue-detection.yml` / `mfa-fatigue-detection.kql` in
  this folder, firing on `ChallengeCount >= 5` denied or timed-out MFA
  challenges for one user inside a 10-minute window
- Higher-confidence variant of the trigger, worth a lower threshold or
  higher severity in a real deployment: the burst is immediately followed
  by a successful sign-in (`ResultType == 0`) for the same user within a
  few minutes of the last challenge, which is the pattern that actually
  indicates the attack worked, not just that it was attempted

**Automated Actions**

1. Revoke the user's active sessions and refresh tokens
   (`Revoke-AzureADUserAllRefreshToken`, or the Microsoft Graph
   `invalidateAllRefreshTokens` action) the moment the trigger condition
   above is met with a following successful sign-in. This is the single
   highest-value automated step, since it kills the session the attacker
   is actually using without waiting on a human.
2. Disable the user's account pending analyst review, rather than resetting
   the password automatically. A scripted password reset on an account
   whose owner has not yet confirmed anything can lock the legitimate user
   out just as effectively as it locks the attacker out, and an analyst
   should confirm this was actually hostile (see Manual Analyst Actions)
   before that step runs.
3. Post the alert, the flagged sign-in's IP/device/location, and a link to
   this playbook into the SOC's incident channel, tagged high severity,
   so a human picks it up immediately rather than sitting in a queue.
4. Query for OAuth app registrations and inbox rule changes made from the
   same session/IP in the following 30 minutes and attach whatever is
   found to the case automatically, since that is exactly the follow-on
   activity the incident report above shows an attacker uses the window
   for, and having it pre-pulled saves the analyst the first several
   minutes of investigation.

**Manual Analyst Actions**

- Confirm with the user directly (a phone call, not email to the
  potentially-compromised mailbox) whether they actually approved a push,
  and if so, whether they recall doing anything unusual around that time
- Review whatever OAuth app registrations or inbox rules the automated
  query above surfaced, and manually revoke/remove anything that does not
  have a legitimate owner or change record
- Check whether the same source IP touched any other accounts in the
  surrounding hours, and pull each of those into the case if so, rather
  than treating this as a single-account incident by default
- Decide whether to re-enable the account after remediation (new password,
  re-enrolled MFA, number matching turned on) or escalate further if the
  scope turns out to be bigger than one account

**Notes**

- Automating a same-session revoke on "burst detected" alone, without
  requiring the follow-on successful sign-in, would generate a real
  operational cost: any user who declines a stray push five times in ten
  minutes gets logged out. I think the successful-sign-in condition is the
  right gate for the fully automated action, and a lower-confidence version
  of the alert (burst with no successful sign-in) should route to a human
  queue instead of triggering revocation, but I have no real MFA-fatigue
  volume to validate that judgment against.
- Number matching (see `incident-report.md`'s Remediation Steps) is a much
  higher-leverage fix than any response automation here, since it prevents
  the reflexive-approve failure mode in the first place. This playbook is
  the reactive half of the fix, not a substitute for the preventive one.
- Same honest caveat as the rest of this repo: nothing in "Automated
  Actions" above has run in a real Sentinel workspace. This is a playbook
  design, written to the shape I would want before building it, not a
  built and tested automation.

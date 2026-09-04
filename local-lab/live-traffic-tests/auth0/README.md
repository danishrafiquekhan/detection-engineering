**A fourth real source — a real identity provider, not just an app or a database**

Cloudflare, MySQL, and Suricata are all real, but none of them are an identity provider. Auth0's free-tier trial (Okta-owned, same free-tier pattern as everything else in this lab) fills that gap — a real IdP with a real System Log, polled into Wazuh the same way as the other three sources.

**Checkpoint-based polling, not file-tailing**

Unlike the other three sources, this isn't a log file being tailed — Auth0's log API is checkpoint-based (`?from=<log_id>` returns only entries after that ID), so `poll_auth0_logs.py` tracks the last-seen `log_id` in a small local checkpoint file and only pulls new entries each cycle. That's a cleaner pattern than file-tailing (no risk of re-processing the same event, no dependency on file position surviving a relay restart) but it does mean credentials with `read:logs` scope have to actually authenticate on a schedule, not just watch a file.

**Least-privilege lesson, found the hard way**

The Auth0 dashboard's application-creation flow authorized this M2M app with nearly the *entire* Management API permission set — user management, client management, connections, encryption keys, everything — instead of just `read:logs`/`read:logs_users`. Easy mistake to make (the "Authorize" step defaults to showing every available scope checked unless you actively narrow it), and a real one: an over-privileged API credential sitting in a home lab is exactly the kind of thing that turns a minor leak into a real incident. Fixed via the Management API itself — `GET /api/v2/client-grants?client_id=...` to find the grant, `PATCH` its `scope` down to just the two read-only log scopes — verified afterward that a write call now correctly returns `403 insufficient_scope`.

**Wazuh has no built-in Auth0 decoder**

Same situation as Cloudflare: `local_rules.xml` here defines a custom rule set (`decoded_as json`, matching on a `log_id` field unique to Auth0's schema to avoid clashing with the Cloudflare rules' `path`-field matching), tagging Auth0's event-type codes into meaningful groups — failed logins, blocked accounts (brute-force lockout), successful/failed Management API calls, and successful/failed M2M client-credentials exchanges (`seccft`/`feccft` — the two types this session's own credential-testing generated real examples of, including a real `feccft` from a deliberately wrong secret used to verify the rule fires).

**Verified, real**

A deliberately wrong client secret produced a real `feccft` event, polled into Wazuh, and correctly fired rule `100026` (level 6, `authentication_failed` group) — `sample-alert.json` is that real alert, IP/client-ID/tenant-name swapped for placeholders before committing.

**Running it**
```bash
export AUTH0_DOMAIN=<your-tenant>.us.auth0.com
export AUTH0_CLIENT_ID=<your M2M app's client ID>
export AUTH0_CLIENT_SECRET=<your M2M app's client secret>
python3 poll_auth0_logs.py
```
Bind-mount `~/securitylab/auth0-lab/wazuh-feed/auth0-events.log` into the Wazuh manager the same way as the other sources, and drop `local_rules.xml`'s `<group name="local,auth0,soc-lab,">` block alongside (not replacing) the existing Cloudflare one in `/var/ossec/etc/rules/local_rules.xml`.

Same on-demand caveat as the other three sources — this is a script you run to generate a test case, not a persistent service. See the top-level `live-traffic-tests/README.md` for why that's a deliberate choice, not a shortcut.

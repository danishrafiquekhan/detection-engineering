**Running Wazuh locally instead of paying for Sentinel**

Wazuh is open source (Apache 2.0), so I run it on my own Mac in Docker instead of spinning up a Sentinel workspace just to have something to point detections at.

**Getting it running**
```bash
chmod +x setup-wazuh.sh
./setup-wazuh.sh
```
This grabs the official wazuh-docker single-node setup, drops it in `~/securitylab/wazuh-docker` (outside this repo on purpose — it generates real TLS certs and those should never end up in git), patches around a permissions bug in their cert generator, and brings the stack up.

Dashboard's at https://localhost, the indexer API at :9200.

**Why Wazuh doesn't replace the Sigma/KQL rules**

I went back and forth on whether to convert my existing sign-in rules to run against Wazuh instead, and decided against it — Wazuh is built for host and network telemetry (agents, file integrity checks, Suricata alerts), not Entra ID cloud logs. Trying to force an Azure AD sign-in rule onto it would've been a fake fit just so I could say "it runs." The KQL rules stay written for Sentinel because that's literally the tool the job postings ask about. Wazuh's job here is different: it's what I actually run when I want to test something end-to-end without waiting on a real Azure tenant. The Suricata setup I already had (`~/securitylab/suricata`) is the obvious next thing to feed into it.

(One nuance worth calling out: Auth0 in `live-traffic-tests/auth0/` is also a cloud identity provider, and it *does* feed into Wazuh — that's not a contradiction of the above. Auth0's System Log has a plain REST API built for polling, the same shape as Cloudflare's request logs; Entra ID's real ingestion path is Sentinel's own analytics rules against `SigninLogs`/`AuditLogs`, a fundamentally different mechanism. Wiring in a pollable REST API is a normal custom-rule integration; faking Entra's native ingestion pipeline on top of Wazuh would still be the fake fit described above.)

**The annoying bug I hit**

Wazuh's own cert generator (`wazuh-certs-generator`) locks its output folder read-only partway through the run, before it finishes writing two of the cert files it needs. First time I ran it, it just failed on `root-ca-manager.pem`/`.key` with a permission error and I assumed I'd done something wrong. Turns out those two files are just a copy of the same root CA the single-node setup already generated — there's no actual second CA involved — so the fix was to copy them over by hand instead of fighting the generator to finish on its own.

Also worth knowing: there's no arm64 build of Wazuh yet, so on my M-series Mac it's running under x86 emulation. Takes noticeably longer to come up healthy than you'd expect from watching `docker ps`.

**One thing I actually did**
Changed the dashboard/API password away from the documented `admin`/`SecretPassword` default. Not scriptable through the obvious API path — the `admin` user is a reserved OpenSearch security-plugin account that rejects direct password-change API calls, and editing `internal_users.yml` alone doesn't take effect on an already-initialized cluster. The real fix: generate a new bcrypt hash with the indexer's own `hash.sh`, update `internal_users.yml`, then push it into the running cluster's security index with `securityadmin.sh` — that's the only step that actually applies it. A plain container restart alone changes nothing here.

**Actually feeding it real traffic**

`live-traffic-tests/` wires in six real, live sources — a Cloudflare Pages site, a MySQL container, Suricata, Auth0, LocalStack, and a Cowrie SSH honeypot — instead of static fixtures. All six produced real alerts. They're intentionally on-demand scripts, not always-on services — see that folder's README for exactly why.

**Watching it happen live**

`dashboard/` is a small loopback-only web page (`python3 dashboard/monitor_server.py`, no dependencies) that shows which of those six sources have alerted recently and streams new alerts as they land in real time, plus the health of the containers behind all of this. See that folder's README for how it reads Wazuh's own alert log without needing a new volume mount.

**Alerts now actually become cases**

`thehive-integration/` closes the gap that existed since this lab first stood up TheHive + Cortex alongside Wazuh: a real alert firing now automatically creates a real TheHive case, verified across three of the four live sources above (Cloudflare, MySQL, Suricata — Auth0 landed after this integration was last checked against TheHive, and Wazuh correctly grouped it under `authentication_failed`, the same group the other three use, so it should behave identically). See that folder's README for how, and for the one real (and harmless) false positive it surfaced along the way.

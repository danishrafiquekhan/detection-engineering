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

**The annoying bug I hit**

Wazuh's own cert generator (`wazuh-certs-generator`) locks its output folder read-only partway through the run, before it finishes writing two of the cert files it needs. First time I ran it, it just failed on `root-ca-manager.pem`/`.key` with a permission error and I assumed I'd done something wrong. Turns out those two files are just a copy of the same root CA the single-node setup already generated — there's no actual second CA involved — so the fix was to copy them over by hand instead of fighting the generator to finish on its own.

Also worth knowing: there's no arm64 build of Wazuh yet, so on my M-series Mac it's running under x86 emulation. Takes noticeably longer to come up healthy than you'd expect from watching `docker ps`.

**One thing to actually do**
Change the dashboard password. It ships with `admin`/`SecretPassword` as the documented default, which is fine for getting started but not something to leave sitting there.

**Actually feeding it real traffic**

`live-traffic-tests/` wires in two real, live sources (a Cloudflare Pages site and a MySQL container) instead of static fixtures. Both produced real alerts. They're intentionally on-demand scripts, not always-on services — see that folder's README for exactly why.

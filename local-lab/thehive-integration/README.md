**Closing the alert-to-case gap**

This lab has run Wazuh and TheHive+Cortex side by side for a while, but they were never actually wired together — a real alert firing in Wazuh never created anything in TheHive. This closes that gap for real, verified against all three live detection sources this lab has (Cloudflare, MySQL, Suricata).

**How it works**

Wazuh has no built-in TheHive integration (its shipped integrations are `maltiverse`, `pagerduty`, `shuffle`, `slack`, `virustotal`), so this is a custom one, following Wazuh's own convention for adding one: a shell wrapper named exactly `custom-<name>` that execs `custom-<name>.py` using Wazuh's bundled Python, both dropped into `/var/ossec/integrations/`. `custom-thehive` is a straight copy of that wrapper pattern (see any of the built-in ones, e.g. `slack`, for the original). `custom-thehive.py` reads the alert JSON Wazuh hands it (as a file path in argv[1]), builds a TheHive case (title, description with the full alert JSON embedded, severity mapped from the Wazuh rule level, tagged with the rule's groups), and POSTs it to TheHive's API — stdlib `urllib` only, since the Wazuh manager container's Python has no third-party packages installed and adding any would be fragile across container recreation.

**The API key is never in this script.** Wazuh passes it as argv[2], sourced from an `<api_key>` tag in the `<integration>` block in ossec.conf — that file lives outside this repo (`~/securitylab/wazuh-docker/`, gitignored for the same reason the TLS certs it generates are) since it holds the real key for this specific lab's TheHive instance.

**Filtering — group, not level**

The integration only fires for alerts in the `attack`, `authentication_failed`, or `ids` groups:
```xml
<integration>
  <name>custom-thehive</name>
  <api_key>YOUR_THEHIVE_API_KEY_HERE</api_key>
  <group>attack,authentication_failed,ids</group>
  <alert_format>json</alert_format>
</integration>
```
A pure level-based filter looked cleaner at first but doesn't actually work here: this repo's own `100011` Cloudflare rule and Wazuh's own `86601` Suricata rule are both level 3, but so is `502` ("Wazuh server started") and routine `rootcheck` housekeeping — a level-only threshold either misses real alerts or floods TheHive with noise. Group filtering is precise: exactly the three real detection sources qualify, routine platform events don't.

**TheHive setup notes**

TheHive's own default `admin@thehive.local`/`secret` account only has platform-management rights (`manageUser`, `manageOrganisation`, etc.) — it explicitly does *not* have `manageCase/create`. Case creation needs a real organisation and a user with the `analyst` profile inside it:
```bash
# as the default admin
curl -X POST http://localhost:9000/api/v1/organisation -b cookies.txt \
  -d '{"name":"soc-lab","description":"..."}'
curl -X POST http://localhost:9000/api/v1/user -b cookies.txt \
  -d '{"name":"Wazuh Integration","login":"wazuh-integration@soc-lab.local","organisation":"soc-lab","profile":"analyst"}'
curl -X POST http://localhost:9000/api/v1/user/wazuh-integration@soc-lab.local/key/renew -b cookies.txt
```
That last call returns the API key that goes in ossec.conf's `<api_key>` tag.

**Verified, real, all three sources**

Each of the three live detection sources this lab has produced a genuine, automatically-created TheHive case: a Suricata network-scan alert, three MySQL authentication-failure alerts (four deliberate wrong-password attempts, three landed after the relay was started mid-attempt), and a Cloudflare dummy-login-endpoint alert. Titles and case numbers from that verification run:
```
15 - Wazuh alert: Suricata: Alert - ET SCAN RDP Connection Attempt from Nmap
14 - Wazuh alert: Cloudflare lab site: request to dummy login endpoint (possible scanner/credential-testing activity)
13 - Wazuh alert: MySQL: authentication failure.
12 - Wazuh alert: MySQL: authentication failure.
11 - Wazuh alert: MySQL: authentication failure.
10 - Wazuh alert: Suricata: Alert - ET SCAN RDP Connection Attempt from Nmap
```
Routine platform noise (Wazuh startup messages, a `rootcheck` false positive from a macOS Docker bind-mount quirk — see the troubleshooting note below) correctly did *not* create cases, confirming the group filter works as intended and this isn't just "everything creates a case."

**A real, harmless false positive this surfaced**

Wazuh's `rootcheck` module flagged `/var/log/cloudflare` and `/var/log/mysql-lab` as suspicious — "Files hidden inside directory... Link count does not match number of files" — which is a legitimate rootkit-hiding detection technique on a real Linux host, correctly firing here on a completely benign cause: Docker Desktop's macOS bind-mount layer (virtiofs) creates a fresh inode when a host-side tool atomically replaces a file (rename-based saves, which many editors and this repo's own tooling do), and the container's cached view of the old inode briefly shows a link-count mismatch. Not a security issue, but a real, reproducible quirk of this specific host/Docker combination worth knowing about if it shows up again.

**One thing this doesn't do**

No `manageCase/update` workflow exists yet — cases get created and then sit there. Closing a case, adding an analyst's findings, or linking related cases together is still a manual TheHive UI step. That's the honest next layer, not something this integration claims to cover.

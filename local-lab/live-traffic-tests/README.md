**Two real traffic sources, actually feeding the Wazuh setup above**

The Wazuh stack in `../` runs, but on its own it has nothing to look at. These two folders wire in real, live traffic — not fixture data — so the local-lab claim ("what I actually run to test something end-to-end") is true rather than aspirational.

**cloudflare/** — a Cloudflare Pages Function (`functions/_middleware.js`) logs every request to a live public site (a synthetic lab target, not a real company). `relay.py` reads `wrangler pages deployment tail`'s live stream, extracts the request events, and appends them to a file bind-mounted into the Wazuh manager container. `local_rules.xml` is a custom rule (Wazuh has no built-in decoder for arbitrary JSON web logs) that fires on hits to the site's dummy `/login.html` endpoint. `sample-alert.json` is a real alert this produced, with the source IP swapped for a documentation-reserved one (198.51.100.0/24) before committing.

**mysql/** — `setup-mysql.sh` brings up a real MySQL 8 container with query/error logging on. `relay.py` tails those logs and reformats matching lines to fit Wazuh's *built-in* `mysql_log` decoder and rule set (`ruleset/decoders/0150-mysql_decoders.xml`, `ruleset/rules/0295-mysql_rules.xml`) — no custom rule needed here, Wazuh already ships real MySQL detection logic, including PCI DSS/GDPR/HIPAA/NIST 800-53 control mapping on the alert. `sample-alert.json` is a real alert from four deliberate failed-login attempts.

**Why these are on-demand scripts, not always-on services**

I decided against running either of these persistently, for reasons that are real limitations, not laziness:

- `wrangler tail` is bound to a specific deployment ID. Every redeploy of the Cloudflare site mints a new one, and the tail silently stops seeing traffic until it's restarted against the new ID. "Persistent" would mean adding deploy-hook logic I haven't built.
- Free-tier Cloudflare has no Logpush or log retention — the live tail *is* the only copy of that traffic. If the relay is down for even a few seconds, those requests are gone, not queued. A dropped connection is silent, permanent data loss, not a backlog.
- Neither `relay.py` handles its source log file getting rotated or truncated. They just hold an open file handle and `readline()` forever. If MySQL's log ever gets rotated externally, the relay keeps watching the orphaned inode and goes quietly blind — no error, no alert that coverage stopped.
- MySQL's `general_log` has no rotation configured and is already unbounded — it hit 13MB from a few minutes of light testing. Left running continuously it will eventually fill disk.
- Running these as bare background processes (not launchd/systemd services) means a Mac restart or sleep just kills them with no supervision and no restart.

None of that is disqualifying for what this is — a way to prove the detection logic actually fires against real, live-generated events instead of static fixtures. It's disqualifying for calling this "production monitoring," which it isn't. Run these on demand when you want to generate a fresh test case; don't leave them running unattended and assume coverage exists.

**Running it**
```bash
# Cloudflare side (from the cf-pages-site project directory)
npx wrangler pages deployment list --project-name=<project>   # get the current deployment ID
npx wrangler pages deployment tail <deployment-id> --project-name=<project> --format=json | python3 cloudflare/relay.py

# MySQL side
bash mysql/setup-mysql.sh
python3 mysql/relay.py
# in another shell, generate real activity, including a few deliberate wrong-password attempts:
docker exec -it soc-lab-mysql mysql -ulabuser -pWrongPassword lab_app -e "SELECT 1"
```
Then check `docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json` on the Wazuh side to watch alerts land.

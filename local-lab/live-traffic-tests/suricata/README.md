**A third real detection source — network IDS, not just app-level logs**

Suricata was built into this lab a while ago but never actually generated a usable alert until now. Two real, unrelated bugs were stopping it, both fixed here.

**Bug 1 — `eve-log` was nested under `logging:` instead of the top-level `outputs:` key.** Suricata's actual schema expects `outputs: [eve-log: ...]` at the document root; `logging:` is only for the engine's own text log. Wrong nesting doesn't error — Suricata just silently never opens the eve.json file, which is exactly what happened. `suricata.yaml` here has the corrected structure.

**Bug 2 — `HOME_NET`/`EXTERNAL_NET` were never defined.** Thousands of ET Open rules reference these address-group variables; undefined, every rule that uses them gets silently disabled at load time ("Rule has unknown source address var and will be disabled"), even though Suricata reports the rule as "loaded successfully." `vars:` now defines them against RFC1918 ranges.

A third, smaller issue: 16 of the ET Open ruleset's Modbus/DNP3 (industrial/SCADA protocol) rules fail to parse when those app-layer protocols are disabled — which they are here, since no ICS/SCADA traffic exists in this lab. `disable.conf` excludes those specific rule groups so the rest of the ruleset (577 rules) loads clean.

**Why live capture instead of a replayed pcap**

Docker Desktop on macOS doesn't give a container real access to the Mac's actual network interfaces, even with host networking — it's a lightweight Linux VM under the hood. Trying to sniff "real" home network traffic from inside Suricata's container wouldn't have worked reliably. The fix: attach Suricata to its own Docker bridge network and generate real, live inter-container traffic for it to actually see — Docker's bridge networking is switched (unicast), so Suricata's own interface only observes traffic to/from itself, not passively between two other containers on the same bridge. The verified alert here came from a real Python socket connection sending the literal bytes of Nmap's RDP-scan cookie (`Cookie: mstshash=nmap`) to a plain netcat listener on port 3389, both on the same bridge as the Suricata container — a real TCP session Suricata's `af-packet` capture actually saw and matched against ET rule 2036252 ("ET SCAN RDP Connection Attempt from Nmap").

`sample-alert.json` is the real resulting Wazuh alert (rule 86601, Wazuh's own built-in Suricata decoder/rule — no custom rule needed, same as MySQL), with IPs swapped for documentation-reserved ones before committing.

**Running it**
```bash
# one-time: fetch a real ruleset (ET Open) into the same volume Suricata reads from
docker run --rm \
  -v ~/securitylab/suricata:/etc/suricata \
  -v <suricata-container-name>:/var/lib/suricata \
  jasonish/suricata:latest suricata-update

# bring up a bridge network and a scan target
docker network create suricata-lab-net
docker run -d --name scan-target --network suricata-lab-net alpine:latest \
  sh -c "apk add --no-cache netcat-openbsd >/dev/null 2>&1; nc -lk -p 3389"

# bring up Suricata on the same network, live capture on its own eth0
docker run -d --name suricata-suricata-1 \
  --network suricata-lab-net --cap-add NET_ADMIN --cap-add SYS_NICE \
  -v ~/securitylab/suricata:/etc/suricata \
  -v ~/securitylab/suricata/logs:/var/log/suricata \
  -v <suricata-container-name>:/var/lib/suricata \
  jasonish/suricata:latest -i eth0 -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules

# generate a real, matching packet from Suricata's own container
docker exec suricata-suricata-1 python3 -c "
import socket
s = socket.create_connection(('scan-target', 3389), timeout=5)
s.sendall(b'\x00\x00\x00\x00\x00Cookie: mstshash=nmap\r\n')
s.close()
"
```
Then bind-mount `suricata/logs/eve.json` into the Wazuh manager (`<localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>`) the same way the Cloudflare/MySQL sources are wired in.

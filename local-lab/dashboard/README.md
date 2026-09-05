**A live status page for the lab, loopback-only**

Every source in `live-traffic-tests/` proves detection logic fires; none of them show it happening in real time in a way that's actually pleasant to watch. This is a small, real, self-contained dashboard for that — one Python file (`monitor_server.py`, stdlib only, no dependencies to install) and one static HTML page, showing which of the six live sources have alerted recently and a live-scrolling feed of alerts as they land, plus the health of the containers that make up the stack.

**How it actually gets the data**

`alerts.json` lives inside a Wazuh-managed Docker *named volume* (`wazuh_logs`), not a host bind mount — so there's no plain file on the Mac's filesystem to just open and tail. The dashboard runs `docker exec -i single-node-wazuh.manager-1 tail -F alerts.json` as a subprocess and reads its stdout line by line; Wazuh writes one compact JSON object per alert per line, so each line is a complete, independently-parseable event. A second background thread polls `docker ps` every 10 seconds for the containers this lab actually cares about. Both feed into an in-memory store, pushed to the browser over Server-Sent Events (`/events`) for anything already connected, with a `/snapshot` JSON endpoint so a fresh page load isn't blank while waiting for the next event.

**Deliberately loopback-only**

The server binds to `127.0.0.1:8787` explicitly, not `0.0.0.0` — this is a personal operator view for whoever's sitting at this Mac, not a service meant to be reachable from the network. No auth exists because none is needed for something that can only ever be reached from the same machine.

**A real, honest limitation: state doesn't survive a restart**

The alert feed and per-source "last seen" times live in the Python process's memory, not a database — restarting `monitor_server.py` clears them back to empty, even though Wazuh's own `alerts.json` history is untouched. That's a deliberate simplicity trade-off, not an oversight: this is a live status view for "is something happening right now," not a historical record — Wazuh's own dashboard (or the alert JSON files this repo already documents) is the place to go for history.

**Verified, real**

Ran against the live Cowrie honeypot source: a real `sshpass`-driven login attempt (bad credential, then a working one, then a command run inside the fake shell) showed up in the live feed within seconds of each event, correctly grouped under "Cowrie honeypot" in the sources panel, with the container-health panel showing all five watched containers up throughout.

**Running it**
```bash
cd local-lab/dashboard
python3 monitor_server.py
# open http://127.0.0.1:8787/
```
Requires Docker running with the Wazuh manager container up (`single-node-wazuh.manager-1` — same name this whole `local-lab/` setup already uses) and the `docker` CLI on `PATH`. Nothing to `pip install`.

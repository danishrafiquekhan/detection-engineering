#!/usr/bin/env python3
"""Live SOC lab status dashboard, served on loopback only.

Reads Wazuh's own alerts.json in real time via `docker exec ... tail -F`
(the file lives inside a named Docker volume, not a host bind mount, so
this is the only way to stream it from the host without adding a new
volume mount) and a periodic `docker ps` snapshot for container health.
No external dependencies — stdlib only, same convention as the other
relay scripts in this lab.

Run:
    python3 monitor_server.py
Then open http://127.0.0.1:8787/ — nothing here binds to a real network
interface, only 127.0.0.1.
"""
import json
import queue
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MANAGER_CONTAINER = "single-node-wazuh.manager-1"
ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
PORT = 8787
STATIC_DIR = Path(__file__).parent / "static"

# Map a rule group to a human label for the "sources" panel.
SOURCE_GROUPS = {
    "cloudflare": "Cloudflare Pages",
    "mysql_log": "MySQL",
    "suricata": "Suricata",
    "ids": "Suricata",
    "auth0": "Auth0",
    "localstack": "LocalStack",
    "cowrie": "Cowrie honeypot",
}

# Containers this lab cares about; anything else running is ignored.
WATCHED_CONTAINERS = [
    "single-node-wazuh.manager-1",
    "single-node-wazuh.indexer-1",
    "single-node-wazuh.dashboard-1",
    "localstack-localstack-1",
    "cowrie-honeypot",
    "thehive",
    "cortex",
]

state_lock = threading.Lock()
recent_alerts = []  # most recent first, capped
last_seen_by_source = {}  # label -> {"time": iso, "rule": desc, "level": n}
container_status = {}  # name -> docker ps status string
subscribers = []  # list of Queue, one per connected SSE client


def broadcast(event: dict):
    with state_lock:
        for q in subscribers:
            q.put(event)


def record_alert(alert: dict):
    rule = alert.get("rule", {})
    groups = rule.get("groups", [])
    label = None
    for g in groups:
        if g in SOURCE_GROUPS:
            label = SOURCE_GROUPS[g]
            break
    if label is None:
        return  # not one of this lab's own custom/tracked sources
    entry = {
        "time": alert.get("timestamp", ""),
        "source": label,
        "rule_id": rule.get("id", ""),
        "level": rule.get("level", 0),
        "description": rule.get("description", ""),
    }
    with state_lock:
        recent_alerts.insert(0, entry)
        del recent_alerts[200:]
        last_seen_by_source[label] = entry
    broadcast({"type": "alert", "data": entry})


def tail_alerts_forever():
    """Streams docker exec tail -F output — Wazuh writes one compact JSON
    object per line in alerts.json, so each line is a complete alert."""
    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "exec", "-i", MANAGER_CONTAINER, "tail", "-F", "-n", "0", ALERTS_PATH],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    record_alert(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            pass
        time.sleep(5)  # manager container restarted or docker hiccuped — retry


def poll_container_status_forever():
    while True:
        try:
            out = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            statuses = {}
            for line in out.strip().splitlines():
                if "\t" not in line:
                    continue
                name, status = line.split("\t", 1)
                if name in WATCHED_CONTAINERS:
                    statuses[name] = status
            with state_lock:
                container_status.clear()
                container_status.update(statuses)
            broadcast({"type": "containers", "data": statuses})
        except Exception:
            pass
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep stdout quiet — this runs interactively

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._serve_file(STATIC_DIR / "index.html", "text/html")
        elif self.path == "/snapshot":
            with state_lock:
                payload = {
                    "alerts": recent_alerts[:50],
                    "sources": last_seen_by_source,
                    "containers": dict(container_status),
                }
            self._serve_json(payload)
        elif self.path == "/events":
            self._serve_sse()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_file(self, path, content_type):
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = queue.Queue()
        with state_lock:
            subscribers.append(q)
        try:
            while True:
                event = q.get()
                data = f"data: {json.dumps(event)}\n\n".encode()
                self.wfile.write(data)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with state_lock:
                if q in subscribers:
                    subscribers.remove(q)


def main():
    threading.Thread(target=tail_alerts_forever, daemon=True).start()
    threading.Thread(target=poll_container_status_forever, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"SOC lab dashboard on http://127.0.0.1:{PORT}/ (loopback only)")
    server.serve_forever()


if __name__ == "__main__":
    main()

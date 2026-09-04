#!/usr/bin/env python3
"""Tails the MySQL container's error.log and general.log, reformats
Connect/Query/Quit and auth-failure lines to match Wazuh's built-in
mysql_log decoder (prematch '^MySQL log:'), and appends them to the
file Wazuh's manager watches via localfile.

Wazuh already ships decoders/rules for this format
(ruleset/decoders/0150-mysql_decoders.xml, ruleset/rules/0295-mysql_rules.xml)
so no custom rule file is needed here, unlike the Cloudflare side — this
script's only job is reformatting real MySQL log lines into the shape
those built-in rules expect.

Run on demand, pointed at the log paths setup-mysql.sh writes to:
    python3 relay.py
"""
import time
import re
import itertools
import threading

ERROR_LOG = "~/securitylab/mysql-lab/logs/error.log"
GENERAL_LOG = "~/securitylab/mysql-lab/logs/general.log"
OUT_PATH = "/var/log/mysql-lab/mysql-events.log"  # bind-mounted into the Wazuh manager container

# matches lines like:
# 2026-09-04T18:23:58.000456Z	    10 Connect	labuser@172.17.0.1 on lab_app using TCP/IP
GENERAL_LINE_RE = re.compile(r"^\S+\s+(\d+)\s+(Connect|Quit|Query)\s*(.*)$")

_seq = itertools.count(1)


def follow(path):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def format_general(line):
    m = GENERAL_LINE_RE.match(line)
    if not m:
        return None
    conn_id, cmd, arg = m.groups()
    ts = time.strftime("%y%m%d %H:%M:%S")
    return f"MySQL log: {ts} {conn_id:>7} {cmd}\t{arg}"


def format_error(line):
    if "Access denied for user" not in line:
        return None
    ts = time.strftime("%y%m%d %H:%M:%S")
    seq = next(_seq)
    return f"MySQL log: {ts} {seq:>7} Connect\t{line.strip()}"


def main():
    import os

    error_log = os.path.expanduser(ERROR_LOG)
    general_log = os.path.expanduser(GENERAL_LOG)

    with open(OUT_PATH, "a", buffering=1) as out:

        def watch_general():
            for line in follow(general_log):
                formatted = format_general(line)
                if formatted:
                    out.write(formatted + "\n")
                    print("mysql general ->", formatted, flush=True)

        def watch_error():
            for line in follow(error_log):
                formatted = format_error(line)
                if formatted:
                    out.write(formatted + "\n")
                    print("mysql error ->", formatted, flush=True)

        t1 = threading.Thread(target=watch_general, daemon=True)
        t2 = threading.Thread(target=watch_error, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()


if __name__ == "__main__":
    main()

# Local lab: Wazuh (open-source SIEM)

**Status: running, verified healthy on 2026-08-29** — cluster status green, manager's analysis/log-collection/rule engine all confirmed running.

This is the self-hosted, fully open-source (Apache 2.0) equivalent of Microsoft Sentinel used to actually run and test detections locally, with no Azure subscription or cost.

## Run it
```bash
chmod +x setup-wazuh.sh
./setup-wazuh.sh
```
This clones the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node deployment into `~/securitylab/wazuh-docker` (kept outside this git repo deliberately — it generates real TLS certs that must never be committed), fixes a permissions quirk in the cert generator, and starts the stack.

- Dashboard: https://localhost
- Indexer (OpenSearch API): https://localhost:9200

## Where this fits vs. the Sigma/KQL rules in this repo
Wazuh is a **host- and network-telemetry** SIEM (agent-based log collection, file integrity monitoring, and it natively ingests Suricata's NIDS alerts) — it isn't a natural home for the Azure-AD-sign-in-log rules already in `sigma-rules/`, which are written for Microsoft Sentinel specifically. They're deliberately kept as-is (Sentinel/KQL is the specific skill the target job postings ask for). Wazuh's role here is different and complementary: it's what actually runs, for free, when there's real host/network telemetry to detect against — e.g. the Suricata NIDS already set up separately (`~/securitylab/suricata`) is a natural next log source to wire into it.

## What I learned / trade-offs
The official cert generator (`wazuh/wazuh-certs-generator`) has a real bug/quirk on macOS: partway through, it `chmod`s the output directory to read-only, before it's finished writing the two manager-cluster cert files — so the very first run always fails on `root-ca-manager.{pem,key}`. Since those two are just the manager's copy of the same root CA (single-node doesn't need a separate cluster CA), the fix is to copy `root-ca.pem`/`root-ca.key` to those names manually rather than trying to force the generator to finish. Also: no arm64 images yet for Wazuh 4.9.2, so it runs under x86 emulation on Apple Silicon — noticeably slower to become healthy than a native stack would be.

## Security note
Nothing in this script or repo contains real certs, keys, or passwords — they're generated fresh, locally, by `setup-wazuh.sh`, into a directory that's never committed. Change the default dashboard password (`admin`/`SecretPassword`) on first login.

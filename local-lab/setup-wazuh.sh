#!/bin/bash
# Reproduces the self-hosted Wazuh SIEM (SIEM/XDR, Apache 2.0, open source) used
# to actually run this lab locally, with no cloud account or cost.
#
# Verified working on macOS (Apple Silicon, under Docker's x86 emulation —
# Wazuh doesn't publish arm64 images yet, so it's slower to start than a
# native image would be, but stable once up).
set -euo pipefail

TARGET_DIR="${1:-$HOME/securitylab/wazuh-docker}"

git clone --depth 1 -b v4.9.2 https://github.com/wazuh/wazuh-docker.git "$TARGET_DIR"
cd "$TARGET_DIR/single-node"

# The official cert generator has a permissions quirk on macOS: it locks the
# certs directory (chmod 500) partway through, before it finishes writing the
# manager-cluster cert pair, so the first run always fails on those two files.
chmod 755 config/wazuh_indexer_ssl_certs/
docker compose -f generate-indexer-certs.yml run --rm generator || true
chmod 755 config/wazuh_indexer_ssl_certs/

cd config/wazuh_indexer_ssl_certs
# root-ca-manager.{pem,key} are just the manager's copy of the same root CA
# (single-node doesn't need a separate cluster CA) — the generator's manager-
# cluster step fails before creating them, so copy them manually.
if [ ! -f root-ca-manager.pem ]; then
  cp root-ca.pem root-ca-manager.pem
  cp root-ca.key root-ca-manager.key
  chmod 400 root-ca-manager.pem root-ca-manager.key
fi
cd ../..

docker compose up -d

echo ""
echo "Wazuh dashboard: https://localhost (default admin/SecretPassword — change this on first login)"
echo "Wazuh indexer:   https://localhost:9200"

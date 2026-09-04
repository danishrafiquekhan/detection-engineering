#!/bin/bash
# Brings up a real MySQL 8 container as a monitored/attacked lab target.
# error_log is always on (small, low-volume, only logs real events like
# auth failures). general_log starts OFF by design — it logs every single
# query including internal housekeeping, so it grows fast if left running
# (13MB from a few minutes of light testing during dev, unbounded from
# there). Turn it on only while actively generating a test scenario, with
# toggle-general-log.sh, then turn it back off.
set -euo pipefail

LOG_DIR="${1:-$HOME/securitylab/mysql-lab/logs}"
mkdir -p "$LOG_DIR"

docker run -d --name soc-lab-mysql \
  -e MYSQL_ROOT_PASSWORD=LabRoot2026 \
  -e MYSQL_DATABASE=lab_app \
  -e MYSQL_USER=labuser \
  -e MYSQL_PASSWORD=LabUser2026 \
  -v "$LOG_DIR:/var/log/mysql" \
  -p 3306:3306 \
  mysql:8.0 \
  --general-log=0 \
  --general-log-file=/var/log/mysql/general.log \
  --log-error=/var/log/mysql/error.log

echo "MySQL lab target starting. Root: root/LabRoot2026, app user: labuser/LabUser2026, db: lab_app"
echo "Connect with MySQL Workbench (or any client) at 127.0.0.1:3306"
echo "general_log starts OFF. Run 'toggle-general-log.sh on' before generating test traffic,"
echo "'toggle-general-log.sh off' when done, and 'toggle-general-log.sh rotate' if it's grown large."

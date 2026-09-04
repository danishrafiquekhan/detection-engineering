#!/bin/bash
# Brings up a real MySQL 8 container as a monitored/attacked lab target,
# with general and error logging on so failed-auth attempts and queries
# actually land somewhere Wazuh can read from.
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
  --general-log=1 \
  --general-log-file=/var/log/mysql/general.log \
  --log-error=/var/log/mysql/error.log

echo "MySQL lab target starting. Root: root/LabRoot2026, app user: labuser/LabUser2026, db: lab_app"
echo "Connect with MySQL Workbench (or any client) at 127.0.0.1:3306"
echo "general_log has no rotation configured here — it grows fast (13MB from a few minutes"
echo "of light testing during dev). Don't leave this running unattended for long."

#!/bin/bash
# Toggles MySQL's general_log on/off at runtime (no restart needed), and
# rotates it when it's grown large. general_log logs every query including
# internal housekeeping, so it's off by default (see setup-mysql.sh) —
# turn it on right before generating a test scenario, off right after.
set -euo pipefail

MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-LabRoot2026}"
LOG_DIR="${LOG_DIR:-$HOME/securitylab/mysql-lab/logs}"
ROTATE_THRESHOLD_BYTES=$((5 * 1024 * 1024))  # 5MB

case "${1:-}" in
  on)
    docker exec soc-lab-mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SET GLOBAL general_log = 'ON';" 2>&1 | grep -v "Warning" || true
    echo "general_log is now ON"
    ;;
  off)
    docker exec soc-lab-mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SET GLOBAL general_log = 'OFF';" 2>&1 | grep -v "Warning" || true
    echo "general_log is now OFF"
    ;;
  rotate)
    size=$(wc -c < "$LOG_DIR/general.log" 2>/dev/null || echo 0)
    if [ "$size" -gt "$ROTATE_THRESHOLD_BYTES" ]; then
      stamp=$(date +%Y%m%d-%H%M%S)
      mv "$LOG_DIR/general.log" "$LOG_DIR/general.log.$stamp"
      : > "$LOG_DIR/general.log"
      echo "rotated: general.log.$stamp ($size bytes) — fresh general.log started"
    else
      echo "general.log is $size bytes, under the ${ROTATE_THRESHOLD_BYTES} byte threshold — not rotating"
    fi
    ;;
  *)
    echo "usage: $0 {on|off|rotate}"
    exit 1
    ;;
esac

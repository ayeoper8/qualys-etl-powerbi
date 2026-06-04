#!/bin/bash
set -euo pipefail

source /app/qualys/.env

LOG_DIR="/app/qualys/logs"
LOG_FILE="$LOG_DIR/etl_$(date +%Y%m%d).log"

# Keep only last 30 daily log files
find "$LOG_DIR" -name "etl_*.log" -mtime +30 -delete

echo "=== ETL run: $(date -u) ===" >> "$LOG_FILE"
cd /app/qualys/src
python3 qualys_etl.py >> "$LOG_FILE" 2>&1

#!/bin/bash
set -euo pipefail
 
source /app/qualys/.env
 
LOG_DIR="/app/qualys/logs"
LOG_FILE="$LOG_DIR/kb_$(date +%Y%m%d).log"
 
echo "=== KB run: $(date -u) ===" >> "$LOG_FILE"
cd /app/qualys/src
python3 qualys_kb.py >> "$LOG_FILE" 2>&1
 

#!/bin/bash
set -euo pipefail
source /app/qualys/.env
cd /app/qualys/src
python3 qualys_etl.py >> /app/qualys/logs/etl.log 2>&1

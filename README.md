# qualys-powerbi-pipeline

Automated vulnerability reporting pipeline — pulls data from the Qualys API, transforms it into clean datasets, and feeds Power BI dashboards for management and security team reporting.

## Overview

A daily ETL pipeline running on a Proxmox LXC container that:

1. Authenticates with the Qualys API
2. Pulls VM detection data across the full asset estate
3. Classifies assets into groups (Servers, Endpoints, Vessels, Network, Hypervisor)
4. Writes clean CSV datasets with a 180-day rolling window
5. Enriches vulnerability data with titles and CVSS scores from the Qualys KnowledgeBase
6. Uploads to Azure Blob Storage for Power BI consumption

## Architecture

```
[Proxmox LXC Container]
        ↓
[qualys_etl.py — daily cron @ 06:00]
        ↓
[output/ — detections.csv, hosts.csv, summary.csv, kb.csv]
        ↓
[Azure Blob Storage — vulnerability-data container]
        ↓
[Power BI Desktop → Power BI Service]
```

## Asset Classification

Assets are classified at ETL time into six groups:

| Group | Classification logic |
|---|---|
| Vessel | NETBIOS hostname contains vessel keywords (MASTER, BRIDGE, CHENG, etc.) |
| Hypervisor | OS string contains VMware ESXi, Hyper-V |
| Network | OS string contains Cisco, Fortinet, Juniper, etc. |
| Server | OS string contains Server, Linux, Ubuntu, Windows 20xx, etc. |
| Endpoint | OS string contains Windows 10/11, macOS |
| Unclassified | No match — reviewed periodically |

Vessel classification runs first and takes priority over OS-based checks.

## Output Datasets

| File | Description | Granularity |
|---|---|---|
| `detections.csv` | One row per detection per day | Detection-level |
| `hosts.csv` | One row per host per day | Host-level |
| `summary.csv` | Aggregated by asset group + severity per day | Summary |
| `kb.csv` | QID lookup table — titles, CVSS scores | Static (weekly refresh) |

All time-series CSVs append daily and maintain a 180-day rolling window.

## Dashboards

Three Power BI pages:

- **Executive Summary** — management-facing, overall posture, trend lines, RAG status
- **Asset Group Detail** — per-fleet breakdown, top vulnerable hosts, vuln age
- **Technical Drill-down** — security team view, row-level detection data, top QIDs

## Project Structure

```
/app/qualys/
├── src/
│   ├── qualys_etl.py       # Main ETL — runs daily via cron
│   └── qualys_kb.py        # KnowledgeBase enrichment — run weekly
├── output/                 # Generated CSVs (not versioned)
├── logs/                   # ETL run logs (not versioned)
├── .env                    # Credentials (not versioned)
└── run_etl.sh              # Cron wrapper
```

## Setup

### Prerequisites

- Python 3.x
- Qualys subscription with API access
- Azure Storage Account with a Blob container
- Azure App Registration with Storage Blob Data Contributor role

### Installation

```bash
# Install dependencies
pip3 install requests azure-storage-blob azure-identity --break-system-packages

# Create directory structure
mkdir -p /app/qualys/{src,output,logs}

# Create service user
useradd -r -s /usr/sbin/nologin qualys
chown -R qualys:qualys /app/qualys
```

### Configuration

Create `/app/qualys/.env`:

```bash
export QUALYS_USERNAME=your_username
export QUALYS_PASSWORD='your_password'
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET='your_client_secret'
export AZURE_STORAGE_ACCOUNT=your_storage_account_name
export AZURE_CONTAINER_NAME=vulnerability-data
```

Lock down permissions:
```bash
chmod 600 /app/qualys/.env
chown qualys:qualys /app/qualys/.env
```

### Cron Schedule

```bash
# Run as qualys user — crontab -e
0 6 * * * /app/qualys/run_etl.sh
```

### Manual Run

```bash
su -s /bin/bash qualys -c "source /app/qualys/.env && python3 /app/qualys/src/qualys_etl.py"
```

## Security Notes

- `.env` is excluded from version control — never commit credentials
- Service runs as a dedicated non-login system user (`qualys`)
- Azure auth uses Service Principal with minimum required permissions (Storage Blob Data Contributor)
- Blob container is private — no anonymous access
- HTTPS enforced on all API and storage connections

## Status

| Component | Status |
|---|---|
| Qualys API connectivity | Complete |
| ETL pipeline | Complete |
| Asset classification | Complete |
| KnowledgeBase enrichment | Complete |
| QDS scoring | Complete |
| Cron automation | Complete |
| Azure Blob upload | In progress |
| Power BI dashboards | In progress |

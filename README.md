# qualys-etl-powerbi

Automated vulnerability reporting pipeline — pulls data from the Qualys API, transforms it into clean datasets, and feeds Power BI dashboards for management and security team reporting.

## Overview

A daily ETL pipeline running on a Proxmox LXC container that:

1. Fetches Qualys API credentials from Azure Key Vault at runtime
2. Authenticates with the Qualys API
3. Pulls VM detection data across the full asset estate
4. Classifies assets into six groups
5. Enriches detections with vulnerability titles, CVSS scores and CVE references
6. Writes clean CSV datasets with rolling retention
7. Uploads to Azure Blob Storage for Power BI consumption

## Architecture

```
[Proxmox LXC Container]
        ↓
[qualys_etl.py — daily cron @ 06:00]
[qualys_kb.py  — weekly cron @ 07:00 Sunday]
        ↓
[Azure Key Vault — credentials fetched at runtime]
        ↓
[output/ — detections.csv, hosts.csv, summary.csv, kb.csv]
        ↓
[Azure Blob Storage — vulnerability-data container]
        ↓
[Power BI Desktop → Power BI Service]
```

## Asset Classification

| Group | Classification logic |
|---|---|
| Vessel | NETBIOS hostname contains vessel keywords (MASTER, BRIDGE, CHENG, CHIEFENG, VSG1, VSG2, etc.) |
| Hypervisor | OS string contains VMware ESXi, Hyper-V |
| Network | OS string contains Cisco, Fortinet, Juniper, etc. |
| Server | OS string contains Server, Linux, Ubuntu, Windows 20xx, etc. |
| Endpoint | OS string contains Windows 10/11, macOS |
| Unclassified | No match — reviewed periodically |

Vessel classification runs first and takes priority over OS-based checks.

## Output Datasets

| File | Description | Retention |
|---|---|---|
| `detections.csv` | One row per detection per day | 180 days |
| `hosts.csv` | One row per host per day | 180 days |
| `summary.csv` | Aggregated by asset group + severity per day | 3 years |
| `kb.csv` | QID lookup — titles, CVSS, CVE IDs | Overwrite weekly |

## Dashboards

- **Executive Summary** — management-facing, trend lines, severity profile, critical risk by asset group
- **Drill Down** — security team view, top vulnerable hosts, vulnerability age, top QIDs by risk score
- **Shipsure** — dedicated view for client-facing production infrastructure
- **Host Detail** — per-host vulnerability drillthrough (requires Power BI Pro)

## Project Structure

```
/app/qualys/
├── src/
│   ├── qualys_etl.py       # Main ETL — daily
│   └── qualys_kb.py        # KnowledgeBase enrichment — weekly
├── output/                 # Generated CSVs (not versioned)
├── logs/                   # Daily logs, 30-day retention
├── .env                    # Azure identity only (not versioned)
├── run_etl.sh              # Daily cron wrapper
└── run_kb.sh               # Weekly cron wrapper
```

## Setup

### Prerequisites

- Python 3.x
- Qualys subscription with API access
- Azure Storage Account with Blob container
- Azure Key Vault with Qualys credentials stored as secrets
- Azure App Registration with Storage Blob Data Contributor and Key Vault Secrets User roles

### Installation

```bash
pip3 install requests azure-storage-blob azure-identity azure-keyvault-secrets --break-system-packages

mkdir -p /app/qualys/{src,output,logs}
useradd -r -s /usr/sbin/nologin qualys
chown -R qualys:qualys /app/qualys
```

### Configuration

Create `/app/qualys/.env`:

```bash
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET='your_client_secret'
export AZURE_STORAGE_ACCOUNT=your_storage_account_name
export AZURE_CONTAINER_NAME=vulnerability-data
export AZURE_KEYVAULT_URL=https://your-keyvault-name.vault.azure.net
```

```bash
chmod 600 /app/qualys/.env
chown qualys:qualys /app/qualys/.env
```

### Key Vault Secrets

| Secret name | Value |
|---|---|
| `qualys-api-username` | Qualys API username |
| `qualys-api-password` | Qualys API password |

### Cron Schedule

```bash
0 6 * * * /app/qualys/run_etl.sh
0 7 * * 0 /app/qualys/run_kb.sh
```

### Manual Run

```bash
su -s /bin/bash qualys -c "source /app/qualys/.env && python3 /app/qualys/src/qualys_etl.py"
```

## Security Notes

- Qualys credentials stored in Azure Key Vault — never on disk
- Service runs as a dedicated non-login system user (`qualys`)
- `.env` is `chmod 600`, owned by `qualys` service user
- Minimum required Azure permissions (Storage Blob Data Contributor, Key Vault Secrets User)
- Blob container is private — no anonymous access
- `.env` excluded from version control

## Status

| Component | Status |
|---|---|
| ETL pipeline | ✅ Complete |
| Asset classification | ✅ Complete |
| KnowledgeBase enrichment | ✅ Complete |
| Azure Key Vault + Blob Storage | ✅ Complete |
| Cron automation | ✅ Complete |
| Power BI dashboards | ✅ Complete |
| Power BI Service publishing | ⏳ Pending Pro licence |

## Known improvements
- Host detail drillthrough — pending Power BI Pro licence
- Azure Arc + Managed Identity — eliminate client secret from `.env`
- SSL verification — test `verify=True` once corporate proxy confirmed
- Extend Qualys authenticated scanning to Linux and network devices
- Teams webhook for ETL failure alerting

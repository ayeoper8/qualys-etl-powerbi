# qualys-etl-powerbi

Automated vulnerability reporting pipeline — pulls data from the Qualys API, transforms it into clean datasets, and feeds Power BI dashboards for management and security team reporting.

## Overview

A daily ETL pipeline running on a Proxmox LXC container that:

1. Fetches Qualys API credentials from Azure Key Vault at runtime
2. Authenticates with the Qualys API
3. Pulls VM detection data across the full asset estate
4. Classifies assets into groups (Servers, Endpoints, Vessels, Network, Hypervisor)
5. Writes clean CSV datasets with a 180-day rolling window
6. Enriches vulnerability data with titles and CVSS scores from the Qualys KnowledgeBase
7. Uploads to Azure Blob Storage for Power BI consumption

## Architecture

```
[Proxmox LXC Container]
        ↓
[qualys_etl.py — daily cron @ 06:00]
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
├── .env                    # Azure identity bootstrapping only (not versioned)
└── run_etl.sh              # Cron wrapper
```

## Setup

### Prerequisites

- Python 3.x
- Qualys subscription with API access
- Azure Storage Account with a Blob container
- Azure Key Vault with Qualys credentials stored as secrets
- Azure App Registration with:
  - Storage Blob Data Contributor role on the storage account
  - Key Vault Secrets User role on the Key Vault

### Installation

```bash
# Install dependencies
pip3 install requests azure-storage-blob azure-identity azure-keyvault-secrets --break-system-packages

# Create directory structure
mkdir -p /app/qualys/{src,output,logs}

# Create service user
useradd -r -s /usr/sbin/nologin qualys
chown -R qualys:qualys /app/qualys
```

### Configuration

Create `/app/qualys/.env` — Azure identity bootstrapping only, no Qualys credentials:

```bash
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET='your_client_secret'
export AZURE_STORAGE_ACCOUNT=your_storage_account_name
export AZURE_CONTAINER_NAME=vulnerability-data
export AZURE_KEYVAULT_URL=https://your-keyvault-name.vault.azure.net
```

Lock down permissions:
```bash
chmod 600 /app/qualys/.env
chown qualys:qualys /app/qualys/.env
```

### Key Vault Secrets

Create the following secrets in Azure Key Vault:

| Secret name | Value |
|---|---|
| `qualys-api-username` | Qualys API username |
| `qualys-api-password` | Qualys API password |

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

- `.env` contains only Azure identity values — no Qualys credentials on disk
- Qualys credentials stored in Azure Key Vault, fetched at runtime
- Service runs as a dedicated non-login system user (`qualys`)
- `.env` is `chmod 600`, owned by `qualys` service user
- Azure App Registration uses minimum required permissions (Storage Blob Data Contributor, Key Vault Secrets User)
- Blob container is private — no anonymous access
- HTTPS enforced on all API and storage connections
- `.env` excluded from version control — never commit credentials

## Planned Improvements

### Azure Arc + Managed Identity
The current setup uses a Service Principal (client secret in `.env`) for Azure authentication.
The target architecture eliminates all credentials from disk using Azure Arc:

1. Register the Proxmox LXC with Azure Arc
2. Azure assigns the container a Managed Identity automatically
3. Assign Key Vault Secrets User and Storage Blob Data Contributor roles to the Managed Identity
4. Scripts authenticate using `ManagedIdentityCredential()` — no credentials on disk at all
5. `.env` file removed entirely

```python
from azure.identity import ManagedIdentityCredential
credential = ManagedIdentityCredential()
```

**Dependencies:** Azure Arc requires outbound HTTPS from the container to
`*.his.arc.azure.com` and `*.guestconfiguration.azure.com`.

### Other planned improvements
- Teams webhook alerting on ETL failure
- Retry logic on Qualys API calls
- Weekly cron job for `qualys_kb.py` KnowledgeBase refresh
- Daily log rotation

## Status

| Component | Status |
|---|---|
| Qualys API connectivity | ✅ Complete |
| ETL pipeline | ✅ Complete |
| Asset classification | ✅ Complete |
| KnowledgeBase enrichment | ✅ Complete |
| QDS scoring | ✅ Complete |
| Cron automation | ✅ Complete |
| Azure Key Vault integration | ✅ Complete |
| Azure Blob Storage upload | ✅ Complete |
| Power BI dashboards | ⏳ In progress |
| Power BI Service publishing | ⏳ In progress |

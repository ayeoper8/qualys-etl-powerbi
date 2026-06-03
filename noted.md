# Qualys ETL — session summary

This file summarises a code review and planning session covering the qualys-etl-powerbi repo.
Upload to Claude on your workstation to continue where you left off.

---

## What was reviewed

- `README.md`
- `src/qualys_etl.py`
- `src/qualys_kb.py`
- `run_etl.sh`

---

## Bugs fixed this session

### 1. Env var name mismatch — `qualys_etl.py`
`os.getenv("username")` and `os.getenv("password")` corrected to
`os.getenv("QUALYS_USERNAME")` and `os.getenv("QUALYS_PASSWORD")` to match the `.env` file
and `qualys_kb.py`.

### 2. Wrong record count — `qualys_kb.py`
`len(records)` after the batch loop referenced only the last batch.
Corrected to `len(all_records)`.

---

## Outstanding bugs to fix

### 3. `verify=False` on all API requests
SSL verification is disabled on every `requests` call in both scripts.
Needs testing on the work machine — simply changing to `verify=True` may work if
Qualys uses a well-known CA. If an SSL error occurs it likely indicates a corporate
proxy doing SSL inspection, which requires a different fix.
**Wait for work machine to test.**

### 4. No Qualys session logout
Neither script logs out of the Qualys session after completing. Qualys has concurrent
session limits — dangling sessions can cause auth failures on the next run.
Add a logout POST at the end of `main()` in both scripts:

```python
session.post(
    f"{BASE_URL}/api/2.0/fo/session/",
    data={"action": "logout"},
    verify=False,
    timeout=30,
)
print("[+] Logged out.")
```

### 5. Partial data on XML parse error
In `fetch_all_hosts`, a mid-run XML parse error saves a debug file and breaks out of
the pagination loop — but the run continues and writes a partial snapshot. That partial
snapshot then blocks re-running today (duplicate protection kicks in).
Should either abort the whole run on parse error, or write a `.partial` marker file
that the duplicate check also catches.

---

## Other code improvements identified (not yet made)

- Retry logic on API calls — `tenacity` library recommended
- `resp.raise_for_status()` should log status code and response snippet before raising
- `run_etl.sh` — add `echo "=== $(date -u) ==="` before the python call, consider
  daily log rotation (`etl_$(date +%Y%m%d).log`)
- `days_open` is calculated at run time not snapshot time — fine for now but worth noting
- Stale flag only applies to Servers — consider a separate threshold for Vessels given
  connectivity constraints
- CVSS fallback path in `qualys_kb.py` could silently pick the wrong value — add a comment
  explaining the two possible schema layouts

---

## Version confusion note
During the session it became apparent the version pushed to GitHub may not be the
most recent local version on the work machine. Review local files on the work machine
before making further changes. Always `git pull` first, then compare against local.

---

## Dashboard recommendations

### Data model
- `kb.csv` as a lookup table joined on QID
- `hosts.csv` as a dimension table
- `detections.csv` as the fact table
- Reconsider whether `summary.csv` needs to exist — Power BI can aggregate natively

### Fields to add to the ETL
- SLA breach flag — e.g. Critical > 14 days, High > 30 days, Medium > 60 days
- `was_previously_fixed` boolean for recurring vulns (Re-Opened status)
- Vessel-level identity field for per-vessel dashboard breakdowns

### Dashboard approach
- Build the technical drill-down first for internal security team use
- Use the 180-day trend data to show direction of travel before presenting to management
- Vessel days-open figures will be high due to connectivity — document a separate SLA
  for vessels or caveat on the dashboard, otherwise it will look like neglect

---

## Architecture improvements identified

### Immediate
- Teams webhook for ETL failure alerting — add to `run_etl.sh`, fire on non-zero exit code

### Planned — Azure Key Vault migration
Currently Qualys credentials are plain text in `.env` (chmod 600, owned by `qualys` service user).

Interim improvement:
- Move `qualys-username` and `qualys-password` to Key Vault secrets
- Scripts fetch at runtime via existing Service Principal (`ClientSecretCredential`)
- `.env` reduced to tenant ID, client ID, client secret only
- Install `azure-keyvault-secrets` pip package

Target architecture — Azure Arc + Managed Identity:
- Register Proxmox LXC with Azure Arc (onboarding script from Azure Portal)
- Azure assigns a Managed Identity to the container
- Assign Key Vault Secrets User role to the Managed Identity
- Scripts use `ManagedIdentityCredential()` — no credentials on disk at all
- Requires outbound HTTPS to `*.his.arc.azure.com` and `*.guestconfiguration.azure.com`

README has been updated with this plan including code examples.

### Longer term
- Structured JSON run manifest written each ETL run for pipeline health monitoring in Power BI
- Simple orchestrator script to chain ETL → KB enrichment with success checking
- Azure SQL or DuckDB if estate grows and CSV joins become a bottleneck

---

## Security posture assessment

| Area | Status | Notes |
|---|---|---|
| Qualys credential | Good | Dedicated API account, no GUI access |
| Service user | Good | Non-login system user, owns credentials |
| File permissions | Good | chmod 600 on .env |
| Azure permissions | Good | Storage Blob Data Contributor scoped to container |
| Credentials at rest | Gap | Plain text .env — Key Vault migration planned |
| LXC vs VM isolation | Gap | Privileged LXC gives host root access to container fs |
| Session logout | Gap | Neither script logs out — fix pending |
| Secret rotation process | Gap | No documented process for expiry/rotation |
| Azure client secret expiry | Check | Verify expiry date in Azure Portal |

---

## Commits made this session
- `fix env var names in etl and kb record count bug`
- `fix kb record count referencing last batch instead of total`
- `add key vault migration plan to readme`
- `add azure arc and managed identity to planned improvements`

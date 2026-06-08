"""
Qualys ETL Script — v4
Pulls VM detection data from Qualys API v4.0 and writes three CSVs:
  - detections.csv   (one row per detection per run — Active/New/Re-Opened + Fixed flagged)
  - hosts.csv        (one row per host per run)
  - summary.csv      (aggregated by asset_group + severity per run — open vulns only)

Each run APPENDS a snapshot_date row — do not overwrite.
Duplicate protection: skips writing if today's snapshot already exists.
On XML parse error: aborts the entire run to avoid partial snapshots.
Credentials fetched from Azure Key Vault at runtime.
CSVs uploaded to Azure Blob Storage after successful run.
Run daily via cron to build trend data.
"""

import requests
import os
import re
import csv
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL   = os.getenv("QUALYS_BASE_URL")
OUTPUT_DIR = Path("/app/qualys/output")
TODAY      = datetime.date.today().isoformat()

# Stale threshold — only flagged for Servers
STALE_DAYS_SERVER = 30

# Detection statuses counted as "open" for summary + severity totals
OPEN_STATUSES = {"Active", "New", "Re-Opened"}

# ── Classification keywords ───────────────────────────────────────────────────

VESSEL_KEYWORDS = [
    # Crew roles
    "MASTER", "CHIEFENG", "FIRSTENG", "CHENG", "CHOFF", "CHIEFOFF",
    "BRIDGE", "BRIDGE1", "CREW", "SPARE",
    # Vessel infrastructure
    "VSHOST", "VSG1", "VSG2", "VESSEL", "GENERAL",
    # Navigation & office
    "BKUPNAV", "NAVBKUP", "SHIPOFFICE"
]

HYPERVISOR_OS_KEYWORDS = [
    "vmware esxi", "esxi", "hyper-v", "xen",
]

NETWORK_OS_KEYWORDS = [
    "cisco ios", "cisco device", "cisco adaptive security",
    "cisco controller", "fortinet", "juniper", "palo alto",
    "aruba", "checkpoint", "f5",
]

SERVER_OS_KEYWORDS = [
    "server", "linux", "ubuntu", "centos", "rhel",
    "debian", "fedora", "suse", "rocky", "alma", "unix",
    # Qualys sometimes omits the word "Server" from these version strings
    "windows 2008", "windows 2012", "windows 2016", "windows 2019", "windows 2022",
]

ENDPOINT_OS_KEYWORDS = [
    "windows 10", "windows 11", "windows vista", "windows 7", "windows 8",
    "macos", "mac os x",
]

SEVERITY_MAP = {
    "5": "Critical",
    "4": "High",
    "3": "Medium",
    "2": "Low",
    "1": "Informational",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def strip_keepalives(xml_text):
    """Qualys injects HTML comments mid-stream that break xml.etree parsing."""
    return re.sub(r'<!--.*?-->', '', xml_text, flags=re.DOTALL)


def classify_asset(netbios, os_text):
    """
    Priority order:
      1. Vessel      — NETBIOS hostname pattern (takes priority over everything)
      2. Hypervisor  — OS string
      3. Network     — OS string
      4. Server      — OS string
      5. Endpoint    — OS string
      6. Unclassified
    """
    nb = (netbios or "").upper()
    for kw in VESSEL_KEYWORDS:
        if kw in nb:
            return "Vessel"

    os_lower = (os_text or "").lower()
    for kw in HYPERVISOR_OS_KEYWORDS:
        if kw in os_lower:
            return "Hypervisor"
    for kw in NETWORK_OS_KEYWORDS:
        if kw in os_lower:
            return "Network"
    for kw in SERVER_OS_KEYWORDS:
        if kw in os_lower:
            return "Server"
    for kw in ENDPOINT_OS_KEYWORDS:
        if kw in os_lower:
            return "Endpoint"

    return "Unclassified"


def days_open(first_found_str):
    """Days between first_found and today. Returns int or empty string."""
    if not first_found_str:
        return ""
    try:
        first = datetime.datetime.fromisoformat(first_found_str.replace("Z", "+00:00"))
        delta = datetime.datetime.now(datetime.timezone.utc) - first
        return delta.days
    except Exception:
        return ""


def days_since_scan(last_scan_str):
    """Days since last scan. Returns int or None."""
    if not last_scan_str:
        return None
    try:
        scanned = datetime.datetime.fromisoformat(last_scan_str.replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - scanned).days
    except Exception:
        return None


def snapshot_exists(filepath, today):
    """Returns True if today's snapshot_date already exists in the CSV."""
    path = Path(filepath)
    if not path.exists():
        return False
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("snapshot_date") == today:
                return True
    return False


def logout(session):
    """Log out of Qualys session — important to avoid hitting concurrent session limits."""
    try:
        session.post(
            f"{BASE_URL}/api/2.0/fo/session/",
            data={"action": "logout"},
            verify=False,
            timeout=30,
        )
        print("[+] Logged out.")
    except Exception as e:
        print(f"[!] Logout failed (non-fatal): {e}")


def get_qualys_credentials():
    """Fetch Qualys credentials from Azure Key Vault at runtime."""
    from azure.identity import ClientSecretCredential
    from azure.keyvault.secrets import SecretClient

    tenant_id     = os.getenv("AZURE_TENANT_ID")
    client_id     = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    vault_url     = os.getenv("AZURE_KEYVAULT_URL")

    if not all([tenant_id, client_id, client_secret, vault_url]):
        print("[!] Azure credentials not set in .env — cannot fetch from Key Vault.")
        return None, None

    try:
        credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        client = SecretClient(vault_url=vault_url, credential=credential)
        username = client.get_secret("qualys-api-username").value
        password = client.get_secret("qualys-api-password").value
        print("[+] Credentials fetched from Key Vault.")
        return username, password
    except Exception as e:
        print(f"[!] Failed to fetch credentials from Key Vault: {e}")
        return None, None


def upload_to_blob():
    """Upload all four CSVs to Azure Blob Storage after ETL completes."""
    from azure.identity import ClientSecretCredential
    from azure.storage.blob import BlobServiceClient

    tenant_id       = os.getenv("AZURE_TENANT_ID")
    client_id       = os.getenv("AZURE_CLIENT_ID")
    client_secret   = os.getenv("AZURE_CLIENT_SECRET")
    storage_account = os.getenv("AZURE_STORAGE_ACCOUNT")
    container_name  = os.getenv("AZURE_CONTAINER_NAME")

    if not all([tenant_id, client_id, client_secret, storage_account, container_name]):
        print("[!] Azure credentials incomplete — skipping upload. Check .env.")
        return

    try:
        credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        blob_service = BlobServiceClient(
            account_url=f"https://{storage_account}.blob.core.windows.net",
            credential=credential
        )
        container = blob_service.get_container_client(container_name)

        files = ["detections.csv", "hosts.csv", "summary.csv", "kb.csv"]
        for filename in files:
            path = OUTPUT_DIR / filename
            if not path.exists():
                print(f"  [!] {filename} not found — skipping")
                continue
            with open(path, "rb") as f:
                container.upload_blob(filename, f, overwrite=True)
            print(f"  uploaded {filename}")

        print("[+] Azure Blob upload complete.")

    except Exception as e:
        print(f"[!] Azure upload failed (non-fatal): {e}")
        print("    Local CSVs are intact — upload will retry on next run.")


def fetch_all_hosts(session):
    """
    Pages through all hosts using the id_min cursor.
    Qualys signals the next page via a WARNING/URL block in the response.
    On XML parse error: raises RuntimeError to abort the entire run.
    """
    all_hosts = []
    params = {
        "action": "list",
        "truncation_limit": 1000,
        "show_qds": 1,
    }
    page = 1

    while True:
        print(f"  [page {page}] fetching (id_min={params.get('id_min', 'start')})...")

        try:
            resp = session.get(
                f"{BASE_URL}/api/4.0/fo/asset/host/vm/detection/",
                params=params,
                verify=False,
                timeout=180,
            )
        except requests.RequestException as e:
            raise RuntimeError(f"HTTP request failed on page {page}: {e}")

        if not resp.ok:
            raise RuntimeError(
                f"HTTP {resp.status_code} on page {page}: {resp.text[:200]}"
            )

        clean_xml = strip_keepalives(resp.text)

        try:
            root = ET.fromstring(clean_xml)
        except ET.ParseError as e:
            debug_path = OUTPUT_DIR / f"debug_page_{page}.xml"
            with open(debug_path, "w", encoding="utf-8") as f:
                f.write(resp.text)
            raise RuntimeError(
                f"XML parse error on page {page}: {e}. "
                f"Raw response saved to {debug_path}. Aborting to avoid partial snapshot."
            )

        hosts = root.findall(".//HOST")
        all_hosts.extend(hosts)
        print(f"  [page {page}] got {len(hosts)} hosts (total so far: {len(all_hosts)})")

        warning = root.find(".//WARNING/URL")
        if warning is not None and warning.text:
            match = re.search(r'id_min=(\d+)', warning.text)
            if match:
                params["id_min"] = match.group(1)
                page += 1
                continue

        break

    return all_hosts


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    # ── Fetch credentials from Key Vault ──────────────────────────────────────
    USERNAME, PASSWORD = get_qualys_credentials()
    if not USERNAME or not PASSWORD:
        print("[!] Could not retrieve credentials — aborting.")
        return

    # ── Duplicate run protection ───────────────────────────────────────────────
    detections_path = OUTPUT_DIR / "detections.csv"
    if snapshot_exists(detections_path, TODAY):
        print(f"[!] Snapshot for {TODAY} already exists — skipping run.")
        print("    Delete today's rows or wait until tomorrow to re-run.")
        return

    # ── Login ─────────────────────────────────────────────────────────────────
    session = requests.Session()
    session.headers.update({"X-Requested-With": "Curl Sample"})

    print("[+] Logging in...")
    login = session.post(
        f"{BASE_URL}/api/2.0/fo/session/",
        data={"action": "login", "username": USERNAME, "password": PASSWORD},
        verify=False,
        timeout=30,
    )
    if "Logged in" not in login.text:
        print("[!] Login failed")
        print(login.text)
        return
    print("[+] Logged in.")

    # ── Fetch — abort on any error, always logout ──────────────────────────────
    try:
        print("[+] Fetching hosts and detections...")
        hosts = fetch_all_hosts(session)
        print(f"[+] Total hosts fetched: {len(hosts)}")

        if not hosts:
            print("[!] No hosts returned — check credentials and API access.")
            return

        # ── Parse ─────────────────────────────────────────────────────────────
        detection_rows = []
        host_rows      = []
        summary        = {}  # (asset_group, severity) → {vuln_count, host_ids}

        for host in hosts:
            host_id     = host.findtext("ID", "")
            ip          = host.findtext("IP", "")
            os_text     = host.findtext("OS", "")
            netbios     = host.findtext("NETBIOS", "")
            dns         = host.findtext("DNS", "")
            last_scan   = host.findtext("LAST_SCAN_DATETIME", "")
            asset_group = classify_asset(netbios, os_text)

            hostname = netbios or (dns.split(".")[0] if dns else f"host_{host_id}")

            scan_age = days_since_scan(last_scan)
            is_stale = (
                asset_group == "Server"
                and scan_age is not None
                and scan_age > STALE_DAYS_SERVER
            )

            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

            for det in host.findall(".//DETECTION"):
                sev_raw     = det.findtext("SEVERITY", "")
                severity    = SEVERITY_MAP.get(sev_raw, "Unknown")
                status      = det.findtext("STATUS", "")
                qid         = det.findtext("QID", "")
                det_type    = det.findtext("TYPE", "")
                first_found = det.findtext("FIRST_FOUND_DATETIME", "")
                last_found  = det.findtext("LAST_FOUND_DATETIME", "")
                qds         = det.findtext("QDS", "")
                is_open     = status in OPEN_STATUSES

                if is_open and severity in sev_counts:
                    sev_counts[severity] += 1

                detection_rows.append({
                    "snapshot_date": TODAY,
                    "host_id":       host_id,
                    "hostname":      hostname,
                    "ip":            ip,
                    "os":            os_text,
                    "asset_group":   asset_group,
                    "qid":           qid,
                    "type":          det_type,
                    "severity":      severity,
                    "status":        status,
                    "is_open":       "1" if is_open else "0",
                    "first_found":   first_found,
                    "last_found":    last_found,
                    "days_open":     days_open(first_found) if is_open else "",
                    "qds":           qds,
                })

                if is_open:
                    key = (asset_group, severity)
                    if key not in summary:
                        summary[key] = {"vuln_count": 0, "host_ids": set()}
                    summary[key]["vuln_count"] += 1
                    summary[key]["host_ids"].add(host_id)

            host_rows.append({
                "snapshot_date":   TODAY,
                "host_id":         host_id,
                "hostname":        hostname,
                "ip":              ip,
                "os":              os_text,
                "asset_group":     asset_group,
                "last_scan":       last_scan,
                "days_since_scan": scan_age if scan_age is not None else "",
                "is_stale":        "1" if is_stale else "0",
                "critical_count":  sev_counts["Critical"],
                "high_count":      sev_counts["High"],
                "medium_count":    sev_counts["Medium"],
                "low_count":       sev_counts["Low"],
                "info_count":      sev_counts["Informational"],
            })

        # ── Write CSVs (append mode) ───────────────────────────────────────────
        print("[+] Writing CSVs...")

        def write_csv(filename, rows, fieldnames):
            path = OUTPUT_DIR / filename
            file_exists = path.exists()
            with open(path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()
                writer.writerows(rows)
            print(f"    wrote {len(rows)} rows → {path}")

        write_csv("detections.csv", detection_rows, [
            "snapshot_date", "host_id", "hostname", "ip", "os", "asset_group",
            "qid", "type", "severity", "status", "is_open",
            "first_found", "last_found", "days_open", "qds",
        ])

        write_csv("hosts.csv", host_rows, [
            "snapshot_date", "host_id", "hostname", "ip", "os", "asset_group",
            "last_scan", "days_since_scan", "is_stale",
            "critical_count", "high_count", "medium_count", "low_count", "info_count",
        ])

        summary_rows = [
            {
                "snapshot_date": TODAY,
                "asset_group":   k[0],
                "severity":      k[1],
                "vuln_count":    v["vuln_count"],
                "host_count":    len(v["host_ids"]),
            }
            for k, v in summary.items()
        ]
        write_csv("summary.csv", summary_rows, [
            "snapshot_date", "asset_group", "severity", "vuln_count", "host_count",
        ])

        # ── Rolling window cleanup (keep 180 days) ─────────────────────────────
        print("[+] Pruning snapshots older than 180 days...")
        cutoff = (datetime.date.today() - datetime.timedelta(days=180)).isoformat()

        for filename in ["detections.csv", "hosts.csv", "summary.csv"]:
            path = OUTPUT_DIR / filename
            if not path.exists():
                continue
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                rows_kept = [r for r in reader if r.get("snapshot_date", "") >= cutoff]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows_kept)
            print(f"    {filename}: kept {len(rows_kept)} rows (cutoff {cutoff})")

        # ── Sanity report ──────────────────────────────────────────────────────
        print(f"\n[+] Done — snapshot {TODAY}")
        print("\n    Asset group breakdown:")
        groups = {}
        for r in host_rows:
            g = r["asset_group"]
            groups[g] = groups.get(g, 0) + 1
        for g, count in sorted(groups.items()):
            print(f"      {g}: {count} hosts")

        stale_servers = [r["hostname"] for r in host_rows if r["is_stale"] == "1"]
        if stale_servers:
            print(f"\n    [!] Stale servers (not scanned in {STALE_DAYS_SERVER}+ days):")
            for h in stale_servers:
                print(f"      {h}")

        unclassified = [r["hostname"] for r in host_rows if r["asset_group"] == "Unclassified"]
        if unclassified:
            print(f"\n    [!] {len(unclassified)} unclassified hosts — review OS/hostname patterns:")
            for h in unclassified[:10]:
                print(f"      {h}")
            if len(unclassified) > 10:
                print(f"      ... and {len(unclassified) - 10} more")

        # ── Upload to Azure Blob Storage ───────────────────────────────────────
        print("[+] Uploading to Azure Blob Storage...")
        upload_to_blob()

    except RuntimeError as e:
        print(f"\n[!] FATAL ERROR — run aborted: {e}")
        print("    No data has been written. Safe to re-run.")

    finally:
        logout(session)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()


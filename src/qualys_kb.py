"""
Qualys KnowledgeBase Enrichment — qualys_kb.py
Fetches vuln metadata for every QID found in detections.csv and writes output/kb.csv.

Columns in kb.csv:
  qid, title, category, vuln_type, cvss_base, cvss3_base,
  pci_flag, published_date, modified_date, cve_list

Run weekly (or on demand). Overwrites kb.csv each run — it's a lookup table,
not a time-series, so overwriting is correct behaviour.

The KnowledgeBase API accepts up to 1000 QIDs per request.
We batch in groups of 500 to stay well within limits.

Credentials fetched from Azure Key Vault at runtime.
kb.csv uploaded to Azure Blob Storage after successful run.
"""

import requests
import os
import re
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL   = os.getenv("QUALYS_BASE_URL")
OUTPUT_DIR = Path("/app/qualys/output")
KB_PATH    = OUTPUT_DIR / "kb.csv"
DET_PATH   = OUTPUT_DIR / "detections.csv"
BATCH_SIZE = 500

# ── Helpers ───────────────────────────────────────────────────────────────────

def strip_keepalives(xml_text):
    """Qualys injects HTML comments mid-stream that break xml.etree parsing."""
    return re.sub(r'<!--.*?-->', '', xml_text, flags=re.DOTALL)


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


def logout(session):
    """Log out of Qualys session."""
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


def upload_kb_to_blob():
    """Upload kb.csv to Azure Blob Storage."""
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

        with open(KB_PATH, "rb") as f:
            container.upload_blob("kb.csv", f, overwrite=True)
        print("[+] kb.csv uploaded to Azure Blob Storage.")

    except Exception as e:
        print(f"[!] Azure upload failed (non-fatal): {e}")
        print("    Local kb.csv is intact.")


def get_qids_from_detections():
    """Read all unique QIDs from detections.csv."""
    qids = set()
    if not DET_PATH.exists():
        print(f"[!] {DET_PATH} not found — run qualys_etl.py first.")
        return []
    with open(DET_PATH, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            qid = row.get("qid", "").strip()
            if qid:
                qids.add(qid)
    return sorted(qids, key=lambda x: int(x))


def fetch_kb_batch(session, qids):
    """
    Fetch KnowledgeBase entries for a list of QIDs.
    Returns a list of dicts, one per QID.
    """
    resp = session.get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/",
        params={
            "action":  "list",
            "ids":     ",".join(str(q) for q in qids),
            "details": "All",
        },
        verify=False,
        timeout=120,
    )
    resp.raise_for_status()

    clean_xml = strip_keepalives(resp.text)

    try:
        root = ET.fromstring(clean_xml)
    except ET.ParseError as e:
        print(f"  [!] XML parse error: {e}")
        return []

    results = []
    for vuln in root.findall(".//VULN"):
        qid = vuln.findtext("QID", "")

        # CVE list — nested under CVE_LIST/CVE/ID
        cves = [c.text for c in vuln.findall(".//CVE_LIST/CVE/ID") if c.text]
        cve_str = "|".join(cves)

        # CVSS v2 — under CVSS/BASE
        # CVSS v3 — under CVSS_V3/BASE
        # Both may be absent for older QIDs
        cvss_base  = vuln.findtext(".//CVSS/BASE", "") or vuln.findtext("CVSS_BASE", "")
        cvss3_base = vuln.findtext(".//CVSS_V3/BASE", "") or vuln.findtext("CVSS3_BASE", "")

        results.append({
            "qid":            qid,
            "title":          vuln.findtext("TITLE", ""),
            "category":       vuln.findtext("CATEGORY", ""),
            "vuln_type":      vuln.findtext("VULN_TYPE", ""),
            "cvss_base":      cvss_base,
            "cvss3_base":     cvss3_base,
            "pci_flag":       vuln.findtext("PCI_FLAG", ""),
            "published_date": vuln.findtext("PUBLISHED_DATETIME", ""),
            "modified_date":  vuln.findtext("MODIFIED_DATETIME", ""),
            "cve_list":       cve_str,
        })

    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    # ── Fetch credentials from Key Vault ──────────────────────────────────────
    USERNAME, PASSWORD = get_qualys_credentials()
    if not USERNAME or not PASSWORD:
        print("[!] Could not retrieve credentials — aborting.")
        return

    # ── Get QIDs ──────────────────────────────────────────────────────────────
    qids = get_qids_from_detections()
    if not qids:
        print("[!] No QIDs found — nothing to do.")
        return
    print(f"[+] Found {len(qids)} unique QIDs to enrich.")

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

    try:
        # ── Fetch in batches ──────────────────────────────────────────────────
        all_records = []
        batches = [qids[i:i+BATCH_SIZE] for i in range(0, len(qids), BATCH_SIZE)]
        print(f"[+] Fetching KnowledgeBase in {len(batches)} batches of up to {BATCH_SIZE}...")

        for i, batch in enumerate(batches, 1):
            print(f"  [batch {i}/{len(batches)}] fetching {len(batch)} QIDs...")
            records = fetch_kb_batch(session, batch)
            all_records.extend(records)
            print(f"  [batch {i}/{len(batches)}] got {len(records)} records")

        print(f"[+] Total KB records fetched: {len(all_records)}")

        # ── Write kb.csv (overwrite — it's a lookup table) ────────────────────
        print(f"[+] Writing {KB_PATH}...")
        fieldnames = [
            "qid", "title", "category", "vuln_type",
            "cvss_base", "cvss3_base", "pci_flag",
            "published_date", "modified_date", "cve_list",
        ]
        with open(KB_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_records)

        print(f"[+] Done — {len(all_records)} QIDs written to {KB_PATH}")

        # ── Sanity check ──────────────────────────────────────────────────────
        missing = len(qids) - len(all_records)
        if missing > 0:
            print(f"\n[!] {missing} QIDs not returned by KnowledgeBase.")
            print("    These may be info-gathering checks or retired QIDs.")

        # Sample output
        print("\n    Sample records:")
        for r in all_records[:5]:
            print(f"      QID {r['qid']:>8}  CVSS3={r['cvss3_base'] or 'n/a':>4}  {r['title'][:60]}")

        # ── Upload to Azure Blob Storage ──────────────────────────────────────
        print("[+] Uploading kb.csv to Azure Blob Storage...")
        upload_kb_to_blob()

    except Exception as e:
        print(f"\n[!] Error: {e}")

    finally:
        logout(session)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()


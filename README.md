# qualys-etl-powerbi
Automated vulnerability reporting pipeline — pulls data from the Qualys API, transforms it into clean datasets, and feeds Power BI dashboards for management and security team reporting.
Overview
A daily ETL pipeline running on a Proxmox LXC container that:

Authenticates with the Qualys API
Pulls VM detection data across the full asset estate
Classifies assets into groups (Servers, Endpoints, Vessels, Network, Hypervisor)
Writes clean CSV datasets with a 180-day rolling window
Enriches vulnerability data with titles and CVSS scores from the Qualys KnowledgeBase
Uploads to Azure Blob Storage for Power BI consumption

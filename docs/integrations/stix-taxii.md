<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# STIX/TAXII Threat Intelligence Export

Malwar supports exporting its threat intelligence data in **STIX 2.1** (Structured Threat Information eXpression) format and serving it via **TAXII 2.1** (Trusted Automated eXchange of Intelligence Information) compatible endpoints.

## What is STIX/TAXII?

**STIX** is an open standard language for describing cyber threat information. It provides a structured, machine-readable format for sharing indicators of compromise (IOCs), threat actors, campaigns, and malware analysis results.

**TAXII** is the companion transport protocol that defines how STIX data is exchanged between systems.

Together, STIX and TAXII enable:

- Automated threat intelligence sharing between security platforms
- Standardized IOC formats that any compliant tool can consume
- Interoperability between Malwar and enterprise SIEM/SOAR solutions

## Data Mapping

| Malwar Entity | STIX Object(s)                  | Description                                |
|---------------|----------------------------------|--------------------------------------------|
| Campaign      | `threat-actor` + `campaign`      | Tracked malware campaigns and attribution  |
| Signature     | `indicator`                      | IOC patterns (IP, domain, URL, hash, etc.) |
| Scan Result   | `malware-analysis`               | Results of scanning SKILL.md files         |
| (System)      | `identity`                       | Malwar itself as the analysis tool         |
| (Linking)     | `relationship`                   | Connects indicators to campaigns           |

### IOC Type to STIX Pattern Mapping

| Malwar IOC Type | STIX Pattern                                |
|-----------------|---------------------------------------------|
| `ip`            | `[ipv4-addr:value = '<value>']`             |
| `domain`        | `[domain-name:value = '<value>']`           |
| `url`           | `[url:value = '<value>']`                   |
| `sha256`        | `[file:hashes.'SHA-256' = '<value>']`       |
| `email`         | `[email-addr:value = '<value>']`            |
| `regex`         | `[artifact:payload_bin = '<value>']`        |

## CLI Usage

```bash
# Export all threat intelligence as STIX 2.1
malwar export stix

# Export a specific campaign
malwar export stix --campaign ClawHavoc

# Write to a file
malwar export stix --output threat-intel.json

# Export in TAXII envelope format
malwar export stix --format taxii
```

## API Endpoints

All endpoints are under `/api/v1/export/` and require the `X-API-Key` header when authentication is enabled.

### STIX Bundle

**`GET /api/v1/export/stix`** -- Returns a complete STIX 2.1 bundle.

### TAXII Discovery

**`GET /api/v1/export/taxii/discovery`** -- Returns the TAXII 2.1 discovery document.

### TAXII Collections

**`GET /api/v1/export/taxii/collections`** -- Lists available TAXII collections.

### TAXII Collection Objects

**`GET /api/v1/export/taxii/collections/{collection_id}/objects`** -- Returns STIX objects from the specified collection.

Default collection ID: `malwar-threat-intel-001`.

## SIEM Integration

### Splunk

1. Install the "Splunk Add-on for TAXII" from Splunkbase
2. Configure Discovery URL: `http://<malwar-host>:8000/api/v1/export/taxii/discovery`
3. Select collection: `malwar-threat-intel-001`
4. Set the polling interval

### Elastic Security

1. Navigate to **Integrations** and search for "Threat Intelligence TAXII"
2. Configure URL: `http://<malwar-host>:8000/api/v1/export/taxii/collections/malwar-threat-intel-001/objects`
3. Set interval: `15m`

### IBM QRadar

1. Navigate to **Threat Intelligence** > **TAXII Feeds**
2. Add Discovery URL: `http://<malwar-host>:8000/api/v1/export/taxii/discovery`
3. Select the `malwar-threat-intel-001` collection

### Generic / Custom Integration

```bash
# Export and pipe to your tool
malwar export stix | your-tool import --format stix

# Scheduled export via cron
0 */4 * * * malwar export stix --output /shared/threat-intel/malwar-latest.json
```

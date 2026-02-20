# STIX/TAXII Threat Intelligence Export

Malwar supports exporting its threat intelligence data in **STIX 2.1** (Structured Threat Information eXpression) format and serving it via **TAXII 2.1** (Trusted Automated eXchange of Intelligence Information) compatible endpoints.

## What is STIX/TAXII?

**STIX** is an open standard language for describing cyber threat information. It provides a structured, machine-readable format for sharing indicators of compromise (IOCs), threat actors, campaigns, and malware analysis results across security tools and organizations.

**TAXII** is the companion transport protocol that defines how STIX data is exchanged between systems. A TAXII server publishes collections of STIX objects that clients (such as SIEM tools) can consume.

Together, STIX and TAXII enable:
- Automated threat intelligence sharing between security platforms
- Standardized IOC formats that any compliant tool can consume
- Interoperability between Malwar and enterprise SIEM/SOAR solutions

## Data Mapping

Malwar maps its internal data model to STIX 2.1 objects as follows:

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
| `hash`          | `[file:hashes.'SHA-256' = '<value>']`       |
| `email`         | `[email-addr:value = '<value>']`            |
| `regex`         | `[artifact:payload_bin = '<value>']`        |

### Verdict Mapping

| Malwar Verdict | STIX `malware-analysis.result` |
|----------------|-------------------------------|
| MALICIOUS      | `malicious`                   |
| SUSPICIOUS     | `suspicious`                  |
| CAUTION        | `suspicious`                  |
| CLEAN          | `benign`                      |

## CLI Usage

### Export all threat intelligence as STIX 2.1

```bash
malwar export stix
```

### Export a specific campaign

```bash
malwar export stix --campaign ClawHavoc
```

### Write to a file

```bash
malwar export stix --output threat-intel.json
```

### Export in TAXII envelope format

```bash
malwar export stix --format taxii
```

### Combine options

```bash
malwar export stix --campaign ClawHavoc --output clawhavoc.json --format taxii
```

## API Endpoints

All endpoints are under `/api/v1/export/` and require the `X-API-Key` header when API key authentication is enabled.

### STIX Bundle

**`GET /api/v1/export/stix`**

Returns a complete STIX 2.1 bundle containing all active campaigns, signatures, and recent scan results.

Query parameters:
- `campaign` (optional): Filter by campaign name

Example response:
```json
{
  "type": "bundle",
  "id": "bundle--a1b2c3d4-...",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--malwar-analysis-tool-00001",
      "name": "Malwar Detection Engine",
      "identity_class": "system"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--...",
      "name": "Known C2 IP",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "pattern_type": "stix",
      "valid_from": "2026-01-15T00:00:00.000Z"
    }
  ]
}
```

### TAXII Discovery

**`GET /api/v1/export/taxii/discovery`**

Returns the TAXII 2.1 discovery document with available API roots.

### TAXII Collections

**`GET /api/v1/export/taxii/collections`**

Lists available TAXII collections. Malwar exposes a single collection containing all threat intelligence data.

### TAXII Collection Objects

**`GET /api/v1/export/taxii/collections/{collection_id}/objects`**

Returns STIX objects from the specified collection in TAXII envelope format.

The default collection ID is `malwar-threat-intel-001`.

Example:
```bash
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:8000/api/v1/export/taxii/collections/malwar-threat-intel-001/objects
```

## SIEM Integration

### Splunk

Splunk Enterprise Security supports STIX/TAXII feeds via the **Splunk Add-on for TAXII**:

1. Install the "Splunk Add-on for TAXII" from Splunkbase
2. Configure a new TAXII feed:
   - Discovery URL: `http://<malwar-host>:8000/api/v1/export/taxii/discovery`
   - Collection: `malwar-threat-intel-001`
3. Set the polling interval (e.g., every 15 minutes)
4. Map the ingested STIX indicators to Splunk's threat intelligence framework

### Elastic Security

Elastic Security can consume STIX data via the **Threat Intel Filebeat module** or the **TAXII integration**:

1. In Kibana, navigate to **Integrations** and search for "Threat Intelligence TAXII"
2. Configure the integration:
   - URL: `http://<malwar-host>:8000/api/v1/export/taxii/collections/malwar-threat-intel-001/objects`
   - Interval: `15m`
3. Indicators will appear in the Elastic Security threat intelligence dashboard

Alternatively, export STIX JSON directly and use Filebeat:

```yaml
filebeat.modules:
  - module: threatintel
    anomali:
      enabled: false
    misp:
      enabled: false
    custom:
      enabled: true
      var.input: file
      var.paths: ["/path/to/malwar-export.json"]
```

### IBM QRadar

QRadar supports STIX/TAXII via the **Threat Intelligence app**:

1. Open the QRadar Admin console
2. Navigate to **Threat Intelligence** > **TAXII Feeds**
3. Add a new feed:
   - Discovery URL: `http://<malwar-host>:8000/api/v1/export/taxii/discovery`
   - Authentication: API Key (set `X-API-Key` header)
4. Select the `malwar-threat-intel-001` collection
5. Configure the polling schedule

### Generic / Custom Integration

For any SIEM or security tool that supports STIX 2.1 JSON:

```bash
# Export and pipe to your tool
malwar export stix | your-tool import --format stix

# Scheduled export via cron
0 */4 * * * malwar export stix --output /shared/threat-intel/malwar-latest.json
```

For tools that support TAXII 2.1:
- Discovery endpoint: `/api/v1/export/taxii/discovery`
- Collections endpoint: `/api/v1/export/taxii/collections`
- Objects endpoint: `/api/v1/export/taxii/collections/malwar-threat-intel-001/objects`

All responses follow the OASIS STIX 2.1 and TAXII 2.1 specifications.

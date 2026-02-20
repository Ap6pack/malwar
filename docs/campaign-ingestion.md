# Campaign Ingestion System

Malwar supports automated ingestion of threat intelligence from external sources. You can import campaigns, IOCs (indicators of compromise), and detection signatures from JSON, CSV, and STIX 2.1 formats.

## Supported Formats

| Format | CLI command | API `source_type` | Description |
|--------|-------------|-------------------|-------------|
| JSON   | `malwar ingest json` | `json` | Structured JSON matching Malwar's import schema |
| CSV    | `malwar ingest csv`  | `csv`  | Simple tabular format with one IOC per row |
| STIX   | `malwar ingest stix` | `stix` | STIX 2.1 JSON bundle (reverse of Malwar's export) |
| HTTP   | `malwar ingest url`  | N/A    | Fetch JSON or CSV from a remote URL |

## JSON Schema Reference

The JSON import format uses the following structure:

```json
{
  "campaigns": [
    {
      "name": "CampaignName",
      "attributed_to": "Threat Actor Name",
      "first_seen": "2026-01-01",
      "iocs": [
        {"type": "domain", "value": "evil.com", "description": "C2 domain"},
        {"type": "ip", "value": "1.2.3.4", "description": "C2 server"},
        {"type": "url", "value": "http://evil.com/payload", "description": "Payload URL"},
        {"type": "hash", "value": "abc123...", "description": "Malware SHA-256"}
      ],
      "signatures": [
        {
          "pattern_type": "exact",
          "pattern_value": "evil.com",
          "ioc_type": "domain",
          "severity": "critical",
          "confidence": 0.95
        }
      ]
    }
  ]
}
```

### Field Reference

**Campaign fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Campaign identifier name |
| `attributed_to` | string | No | Threat actor attribution |
| `first_seen` | string | No | First seen date (YYYY-MM-DD) |
| `iocs` | array | No | List of IOC objects |
| `signatures` | array | No | List of signature objects |

**IOC fields:**

| Field | Type | Required | Values |
|-------|------|----------|--------|
| `type` | string | Yes | `ip`, `domain`, `url`, `hash` |
| `value` | string | Yes | The indicator value |
| `description` | string | No | Human-readable description |

**Signature fields:**

| Field | Type | Required | Values |
|-------|------|----------|--------|
| `pattern_type` | string | Yes | `exact`, `regex`, `fuzzy`, `ioc` |
| `pattern_value` | string | Yes | The pattern to match |
| `ioc_type` | string | Yes | `ip`, `domain`, `url`, `hash` |
| `severity` | string | No | `critical`, `high`, `medium`, `low`, `info` (default: `medium`) |
| `confidence` | float | No | 0.0 to 1.0 (default: 0.8) |

## CSV Format Reference

The CSV format expects four columns with a header row:

```csv
campaign,ioc_type,ioc_value,severity
APT-Example,domain,evil.com,critical
APT-Example,ip,1.2.3.4,high
OtherCampaign,url,http://bad.example.com,medium
```

**Column definitions:**

| Column | Required | Description |
|--------|----------|-------------|
| `campaign` | Yes | Campaign name (rows with the same name are grouped) |
| `ioc_type` | Yes | IOC type: `ip`, `domain`, `url`, `hash` |
| `ioc_value` | Yes | The indicator value |
| `severity` | Yes | `critical`, `high`, `medium`, `low`, `info` |

Each row produces both an IOC and an exact-match detection signature.

## STIX 2.1 Bundle Format

Malwar can ingest STIX 2.1 JSON bundles, including those exported by Malwar itself. The importer extracts:

- **Campaign** objects with `first_seen` and `last_seen` dates
- **Threat-actor** objects linked via `attributed-to` relationships
- **Indicator** objects with STIX patterns (mapped back to IOC types)
- **Relationship** objects (`indicates`, `attributed-to`)

Supported STIX patterns:
- `[ipv4-addr:value = '...']` maps to IOC type `ip`
- `[domain-name:value = '...']` maps to IOC type `domain`
- `[url:value = '...']` maps to IOC type `url`
- `[file:hashes.'SHA-256' = '...']` maps to IOC type `hash`

## CLI Usage Examples

### Import from JSON file

```bash
malwar ingest json threats.json
```

### Import from CSV file

```bash
malwar ingest csv indicators.csv
```

### Import from STIX bundle

```bash
malwar ingest stix bundle.json
```

### Fetch and import from HTTP URL

```bash
# JSON feed (default)
malwar ingest url https://feeds.example.com/threats.json

# CSV feed
malwar ingest url https://feeds.example.com/indicators.csv --format csv
```

### Example output

```
Import complete:
  Campaigns added:    2
  Campaigns updated:  0
  Signatures added:   8
  Signatures skipped: 0
```

## API Endpoint Reference

### POST /api/v1/ingest

Import threat intelligence data via the REST API.

**Authentication:** Requires `X-API-Key` header (when API keys are configured).

**Request body:**

```json
{
  "source_type": "json",
  "data": "{\"campaigns\": [...]}"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_type` | string | Yes | Format: `json`, `csv`, or `stix` |
| `data` | string | Yes | The content to import (stringified) |

**Response (200 OK):**

```json
{
  "campaigns_added": 1,
  "campaigns_updated": 0,
  "signatures_added": 3,
  "signatures_skipped": 0,
  "errors": []
}
```

**Error responses:**

| Status | Description |
|--------|-------------|
| 401 | Missing API key |
| 403 | Invalid API key |
| 422 | Invalid payload or import failed |

**Example using curl:**

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "source_type": "json",
    "data": "{\"campaigns\":[{\"name\":\"TestCampaign\",\"iocs\":[{\"type\":\"domain\",\"value\":\"evil.com\"}],\"signatures\":[{\"pattern_type\":\"exact\",\"pattern_value\":\"evil.com\",\"ioc_type\":\"domain\",\"severity\":\"critical\"}]}]}"
  }'
```

## Deduplication Behavior

The importer uses the following deduplication strategy:

1. **Campaign matching:** Campaigns are matched by `name`. If a campaign with the same name already exists, it is considered a duplicate.

2. **Signature matching:** Signatures are matched by the combination of campaign name and `pattern_value`. If a signature with the same pattern value already exists for the same campaign, it is skipped.

3. **Merge mode (default):** When importing into an existing campaign, new IOCs are merged into the campaign's IOC list. Existing IOCs (matched by value) are not duplicated.

4. **Skip mode:** If merge is disabled, existing campaigns are left unchanged but new signatures are still imported if they don't already exist.

### Import result counts

| Field | Description |
|-------|-------------|
| `campaigns_added` | Number of new campaigns created |
| `campaigns_updated` | Number of existing campaigns updated with new IOCs |
| `signatures_added` | Number of new signatures created |
| `signatures_skipped` | Number of signatures that already existed |
| `errors` | List of error messages (if any) |

<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

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

```json
{
  "campaigns": [
    {
      "name": "CampaignName",
      "attributed_to": "Threat Actor Name",
      "first_seen": "2026-01-01",
      "iocs": [
        {"type": "domain", "value": "evil.com", "description": "C2 domain"},
        {"type": "ip", "value": "1.2.3.4", "description": "C2 server"}
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

## CSV Format Reference

```csv
campaign,ioc_type,ioc_value,severity
APT-Example,domain,evil.com,critical
APT-Example,ip,1.2.3.4,high
OtherCampaign,url,http://bad.example.com,medium
```

## CLI Usage Examples

```bash
# Import from JSON file
malwar ingest json threats.json

# Import from CSV file
malwar ingest csv indicators.csv

# Import from STIX bundle
malwar ingest stix bundle.json

# Fetch and import from HTTP URL
malwar ingest url https://feeds.example.com/threats.json
malwar ingest url https://feeds.example.com/indicators.csv --format csv
```

## API Endpoint

### POST /api/v1/ingest

**Request body:**

```json
{
  "source_type": "json",
  "data": "{\"campaigns\": [...]}"
}
```

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

## Deduplication Behavior

1. **Campaign matching:** Campaigns are matched by `name`.
2. **Signature matching:** Signatures are matched by campaign name + `pattern_value`.
3. **Merge mode (default):** New IOCs are merged into existing campaigns.
4. **Skip mode:** Existing campaigns are left unchanged but new signatures are still imported.

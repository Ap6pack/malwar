# Notification Channels

malwar can send notifications when scans complete, threats are detected, or scans fail. Supported channels include Slack, Microsoft Teams, PagerDuty, email (SMTP), and generic webhooks.

## Configuration

All settings use the `MALWAR_` prefix and can be set via environment variables or a `.env` file.

### Enabling channels

Set `MALWAR_NOTIFICATION_CHANNELS` to a comma-separated list of channel names to enable:

```bash
MALWAR_NOTIFICATION_CHANNELS=slack,pagerduty,email
```

If omitted, malwar auto-detects which channels to activate based on which credentials are present.

### Slack

```bash
MALWAR_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Messages use Slack [Block Kit](https://api.slack.com/block-kit) formatting with structured fields for verdict, risk score, findings, and scan metadata.

### Microsoft Teams

```bash
MALWAR_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
```

Messages use [Adaptive Cards](https://adaptivecards.io/) v1.4 with a fact set and findings list.

### PagerDuty

```bash
MALWAR_PAGERDUTY_ROUTING_KEY=your-integration-routing-key
```

PagerDuty incidents are created via [Events API v2](https://developer.pagerduty.com/docs/events-api-v2/overview/) **only** for `MALICIOUS` and `SUSPICIOUS` verdicts. Clean and caution scans are silently filtered. Each incident includes:

- A dedup key based on the scan ID (prevents duplicate alerts).
- Severity mapping: MALICIOUS -> critical, SUSPICIOUS -> error.
- Custom details with findings summary.

### Email (SMTP)

```bash
MALWAR_SMTP_HOST=smtp.example.com
MALWAR_SMTP_PORT=587
MALWAR_SMTP_USER=alerts@example.com
MALWAR_SMTP_PASSWORD=secret
MALWAR_SMTP_USE_TLS=true
MALWAR_SMTP_FROM=malwar@example.com
MALWAR_SMTP_TO=security-team@example.com,oncall@example.com
```

Emails are sent as HTML with a styled template containing verdict, risk score, findings table, and scan metadata. Multiple recipients are supported (comma-separated in `MALWAR_SMTP_TO`).

### Generic Webhook

The legacy webhook settings also work as a notification channel:

```bash
MALWAR_WEBHOOK_URL=https://your-endpoint.example.com/hook
MALWAR_WEBHOOK_URLS=https://hook1.example.com,https://hook2.example.com
MALWAR_WEBHOOK_SECRET=your-hmac-secret
MALWAR_WEBHOOK_VERDICTS=MALICIOUS,SUSPICIOUS
```

When a secret is configured, an `X-Malwar-Signature` header with HMAC-SHA256 is included.

## API Endpoints

### List channels

```
GET /api/v1/notifications/channels
```

Returns the configured channels and their status.

**Response:**

```json
[
  {
    "name": "slack",
    "configured": true,
    "event_types": ["scan_complete", "threat_found", "scan_failed"],
    "verdicts": ["CAUTION", "CLEAN", "MALICIOUS", "SUSPICIOUS"],
    "min_risk_score": 0
  }
]
```

### Test notifications

```
POST /api/v1/notifications/test
```

Send a test notification to verify channel configuration.

**Request body (optional):**

```json
{
  "channel": "slack"
}
```

Omit the body or set `channel` to `null` to test all channels.

**Response:**

```json
[
  {
    "channel": "slack",
    "success": true
  }
]
```

## CLI Commands

### Test a channel

```bash
malwar notify test --channel slack
```

Omit `--channel` to test all configured channels.

### List channels

```bash
malwar notify channels
```

## Event Types

| Event Type     | Description                                      |
|----------------|--------------------------------------------------|
| scan_complete  | Scan finished with CLEAN or CAUTION verdict      |
| threat_found   | Scan detected MALICIOUS or SUSPICIOUS content    |
| scan_failed    | Scan encountered an error                        |

## Architecture

```
ScanResult
    |
    v
NotificationEvent.from_scan_result()
    |
    v
NotificationRouter.dispatch()
    |
    +---> SlackChannel.send()
    +---> TeamsChannel.send()
    +---> PagerDutyChannel.send()
    +---> EmailChannel.send()
    +---> GenericWebhookChannel.send()
```

The router applies per-channel filters (verdict, risk score, event type) before dispatching. Channel failures are logged but never block the scan pipeline.

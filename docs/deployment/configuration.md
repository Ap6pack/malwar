<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Configuration

All settings are managed via environment variables with the `MALWAR_` prefix, loaded from `.env` files using Pydantic Settings.

---

## Environment Variables

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_DB_PATH` | `malwar.db` | Path to the SQLite database file |

### API Server

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_API_HOST` | `127.0.0.1` | API server bind address |
| `MALWAR_API_PORT` | `8000` | API server bind port |
| `MALWAR_API_WORKERS` | `1` | Number of Uvicorn worker processes |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_API_KEYS` | *(empty)* | Comma-separated API keys. Empty = auth disabled. |

### LLM (Layer 3)

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_ANTHROPIC_API_KEY` | *(empty)* | Anthropic API key for LLM analysis |
| `MALWAR_LLM_MODEL` | `claude-sonnet-4-20250514` | LLM model to use |
| `MALWAR_LLM_MAX_TOKENS` | `4096` | Maximum tokens for LLM response |
| `MALWAR_LLM_TEMPERATURE` | `0.0` | LLM sampling temperature |
| `MALWAR_LLM_SKIP_BELOW_RISK` | `15` | Skip LLM if risk score is below this threshold |

### URL Crawler (Layer 2)

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_CRAWLER_MAX_URLS` | `10` | Max URLs to fetch per scan |
| `MALWAR_CRAWLER_TIMEOUT` | `5.0` | URL fetch timeout in seconds |
| `MALWAR_CRAWLER_MAX_REDIRECTS` | `3` | Max HTTP redirects to follow |
| `MALWAR_CRAWLER_MAX_RESPONSE_BYTES` | `1048576` | Max response body size (1 MB) |
| `MALWAR_CRAWLER_CONCURRENCY` | `5` | Max concurrent URL fetches |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_RATE_LIMIT_RPM` | `60` | API rate limit (requests per minute per IP) |

### Scanning

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_SCAN_MAX_FILE_SIZE` | `524288` | Max SKILL.md file size (512 KB) |

### Webhooks

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_WEBHOOK_URL` | *(empty)* | URL to POST webhook payloads to |
| `MALWAR_WEBHOOK_SECRET` | *(empty)* | HMAC secret for signing payloads |
| `MALWAR_WEBHOOK_VERDICTS` | `MALICIOUS,SUSPICIOUS` | Comma-separated list of verdicts that trigger webhooks |
| `MALWAR_WEBHOOK_URLS` | *(empty)* | Legacy: comma-separated list of multiple webhook URLs |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_LOG_LEVEL` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |
| `MALWAR_LOG_FORMAT` | `json` | Log format: `json` or `text` |

---

## Configuration File

Create a `.env` file in the project root:

```bash
# Required for LLM analysis (Layer 3)
MALWAR_ANTHROPIC_API_KEY=sk-ant-your-key-here

# Recommended: Set API authentication keys
MALWAR_API_KEYS=your-secret-key-1,your-secret-key-2

# Optional: Customize database location
MALWAR_DB_PATH=/var/lib/malwar/malwar.db

# Optional: Configure logging
MALWAR_LOG_LEVEL=INFO
MALWAR_LOG_FORMAT=json

# Optional: Webhook notifications
MALWAR_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/xxx
MALWAR_WEBHOOK_SECRET=your-webhook-signing-secret
```

---

## API Key Configuration

### Generating API Keys

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Configuring Multiple Keys

```bash
MALWAR_API_KEYS=key-for-ci-pipeline,key-for-admin-dashboard,key-for-monitoring
```

### Authentication Behavior

- When `MALWAR_API_KEYS` is empty or unset, authentication is **disabled** (open access).
- When configured, every request must include a valid `X-API-Key` header.
- The `/api/v1/health` endpoint does not require authentication.

---

## LLM Cost Management

Layer 3 (LLM analysis) calls the Anthropic API and incurs costs. Cost control measures:

1. **Risk threshold:** The LLM layer is automatically skipped when the risk score from prior layers is below `MALWAR_LLM_SKIP_BELOW_RISK` (default: 15). Clean skills never trigger an API call.
2. **Selective layers:** Use `--no-llm` in CLI or `"use_llm": false` in API requests.
3. **Layer selection:** Use `--layers rule_engine,threat_intel` to run only free layers.
4. **Model selection:** Configure `MALWAR_LLM_MODEL` for cost-effective models.

---

## Logging

### JSON Format (default)

```json
{"timestamp": "2026-02-20 10:30:00", "level": "INFO", "logger": "malwar.scanner.pipeline", "message": "Scan abc123 complete: verdict=MALICIOUS risk=95 findings=5 duration=1250ms"}
```

### Text Format

```
2026-02-20 10:30:00 [INFO] malwar.scanner.pipeline: Scan abc123 complete: ...
```

### Sensitive Data Redaction

API keys and tokens in log messages are automatically redacted. Patterns for Anthropic keys, OpenAI keys, AWS keys, GitHub tokens, and Bearer tokens are matched and truncated.

---

## Webhook Configuration

### Setup

```bash
MALWAR_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/xxx
MALWAR_WEBHOOK_SECRET=your-secret
MALWAR_WEBHOOK_VERDICTS=MALICIOUS,SUSPICIOUS
```

### HMAC Signing

When `MALWAR_WEBHOOK_SECRET` is configured, each webhook includes an `X-Malwar-Signature` header with an HMAC-SHA256 hex digest.

### Retry Logic

Webhook delivery retries up to 3 times with exponential backoff (1s, 2s, 4s). Failures are logged but never block the scan pipeline.

---

## CORS

The API server allows `http://localhost:3000` for the Vite development server. For production deployments where the frontend is served from the same origin, no CORS configuration is needed.

---

## Health Checks

| Endpoint | Purpose | Auth Required |
|----------|---------|---------------|
| `GET /api/v1/health` | Server is running | No |
| `GET /api/v1/ready` | Database is connected | No |

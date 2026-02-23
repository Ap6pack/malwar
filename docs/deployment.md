<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Deployment Guide

## Prerequisites

- Python 3.13 or later
- Node.js 20 (for building the frontend, optional)
- Docker (for containerized deployment, optional)

---

## Option 1: pip install

### Install from Source

```bash
# Clone the repository
git clone https://github.com/Ap6pack/malwar.git
cd malwar

# Install the package
pip install .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Initialize the Database

```bash
malwar db init
```

This creates the SQLite database (default: `malwar.db` in the current directory), applies the schema, and inserts seed data including the ClawHavoc campaign intelligence.

### Configure Environment

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Required for LLM analysis (Layer 3)
MALWAR_ANTHROPIC_API_KEY=sk-ant-your-key-here

# Recommended: Set API authentication keys
MALWAR_API_KEYS=your-secret-key-1,your-secret-key-2

# Optional: Customize database location
MALWAR_DB_PATH=/var/lib/malwar/malwar.db
```

### Run the CLI

```bash
# Scan a file
malwar scan path/to/SKILL.md

# Start the API server
malwar serve
```

### Build the Frontend (Optional)

If you want the web dashboard:

```bash
cd web
npm ci
npm run build
cd ..
```

The compiled frontend assets in `web/dist/` are automatically served by the API server.

---

## Option 2: Docker

### Build the Image

The multi-stage Dockerfile builds both the frontend and backend:

```bash
docker build -t malwar .
```

**Stage 1 (frontend-build):** Installs Node.js dependencies and builds the React frontend.
**Stage 2 (runtime):** Installs Python dependencies and copies the compiled frontend assets.

### Run the Container

```bash
docker run -d \
  --name malwar \
  -p 8000:8000 \
  -v malwar-data:/app/data \
  -e MALWAR_API_KEYS="your-secret-key" \
  -e MALWAR_ANTHROPIC_API_KEY="sk-ant-your-key" \
  malwar
```

**Volume:** The `/app/data` volume persists the SQLite database between container restarts. The database path inside the container is `/app/data/malwar.db`.

**Port:** The API server listens on port 8000 inside the container.

### Docker Environment Variables

Pass environment variables at runtime:

```bash
docker run -d \
  -p 8000:8000 \
  -v malwar-data:/app/data \
  -e MALWAR_API_KEYS="key1,key2" \
  -e MALWAR_ANTHROPIC_API_KEY="sk-ant-..." \
  -e MALWAR_LOG_LEVEL="INFO" \
  -e MALWAR_RATE_LIMIT_RPM="120" \
  -e MALWAR_WEBHOOK_URLS="https://hooks.slack.com/..." \
  malwar
```

---

## Option 3: docker-compose

The simplest deployment method for production:

### docker-compose.yml

```yaml
services:
  malwar:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - malwar-data:/app/data
    environment:
      - MALWAR_API_KEYS=${MALWAR_API_KEYS}
      - MALWAR_ANTHROPIC_API_KEY=${MALWAR_ANTHROPIC_API_KEY}
    restart: unless-stopped

volumes:
  malwar-data:
```

### Deploy

```bash
# Create .env with your configuration
cp .env.example .env
# Edit .env with your API keys

# Build and start
docker compose up -d

# View logs
docker compose logs -f malwar

# Stop
docker compose down
```

---

## Environment Configuration

### Required Variables

| Variable | Purpose |
|---|---|
| `MALWAR_ANTHROPIC_API_KEY` | Enables Layer 3 (LLM analysis). Without this, LLM analysis is skipped. |

### Strongly Recommended Variables

| Variable | Purpose |
|---|---|
| `MALWAR_API_KEYS` | Enables API authentication. Without this, the API is open to anyone. |
| `MALWAR_DB_PATH` | Set to a persistent location (e.g., `/var/lib/malwar/malwar.db`). |

### All Environment Variables

See the full list in the [CLI Reference](guide/cli-reference.md#environment-variables).

---

## Database Setup

### SQLite

malwar uses SQLite with WAL (Write-Ahead Logging) mode for the storage backend. The database is initialized automatically when the API server starts or when `malwar db init` is run.

**Schema creation** is idempotent -- tables are created with `IF NOT EXISTS` and seed data uses `INSERT OR IGNORE`.

**Tables:**
- `campaigns` -- Tracked malware campaigns
- `scans` -- Scan results
- `findings` -- Individual threat findings (FK to scans)
- `signatures` -- Threat intelligence signatures (FK to campaigns)
- `publishers` -- Author/publisher reputation data
- `url_analysis` -- URL fetch results (FK to scans)

**Indexes** are created on frequently queried columns for performance.

### Database Location

The database file location is controlled by `MALWAR_DB_PATH`:

| Deployment | Default Path | Recommended Path |
|---|---|---|
| Development | `./malwar.db` | `./malwar.db` |
| Docker | `/app/data/malwar.db` | Volume-mounted `/app/data/malwar.db` |
| Production | `./malwar.db` | `/var/lib/malwar/malwar.db` |

### Backup

SQLite databases can be backed up by copying the file:

```bash
# Stop writes first (or use SQLite backup API)
cp /var/lib/malwar/malwar.db /backups/malwar-$(date +%Y%m%d).db
```

For zero-downtime backups with WAL mode, use the SQLite `.backup` command:

```bash
sqlite3 /var/lib/malwar/malwar.db ".backup /backups/malwar-$(date +%Y%m%d).db"
```

---

## API Key Configuration

### Generating API Keys

API keys can be any string. For production, generate cryptographically random keys:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Configuring Multiple Keys

Set `MALWAR_API_KEYS` as a comma-separated list:

```bash
MALWAR_API_KEYS=key-for-ci-pipeline,key-for-admin-dashboard,key-for-monitoring
```

### Authentication Behavior

- When `MALWAR_API_KEYS` is empty or unset, authentication is **disabled** (open access).
- When configured, every request must include a valid `X-API-Key` header.
- The `/api/v1/health` endpoint does not require authentication.

---

## Production Considerations

### Reverse Proxy

In production, run malwar behind a reverse proxy (nginx, Caddy, or a cloud load balancer):

```nginx
# nginx configuration example
upstream malwar {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl;
    server_name malwar.example.com;

    ssl_certificate /etc/ssl/certs/malwar.crt;
    ssl_certificate_key /etc/ssl/private/malwar.key;

    location / {
        proxy_pass http://malwar;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### TLS/HTTPS

The malwar API server does not handle TLS directly. Always terminate TLS at a reverse proxy or load balancer in production.

### Workers

For production workloads, increase the number of Uvicorn workers:

```bash
malwar serve --workers 4
# Or via docker-compose:
# command: ["python", "-m", "malwar", "serve", "--host", "0.0.0.0", "--workers", "4"]
```

**Note:** SQLite supports concurrent reads but serializes writes. For high-throughput write workloads, consider running a single writer process with multiple reader processes.

### Rate Limiting

The built-in rate limiter operates per-IP, in-memory, per-process. In multi-worker or multi-instance deployments, each worker maintains its own rate limit state. For production rate limiting across instances, use a reverse proxy rate limiter or a Redis-backed solution.

Default: 60 requests per minute per IP. Configure with `MALWAR_RATE_LIMIT_RPM`.

### Logging

malwar supports two log formats:

- **JSON** (default) -- Structured logs suitable for log aggregation systems (ELK, Datadog, Splunk):
  ```json
  {"timestamp": "2026-02-20 10:30:00", "level": "INFO", "logger": "malwar.scanner.pipeline", "message": "Scan abc123 complete: verdict=MALICIOUS risk=95 findings=5 duration=1250ms"}
  ```

- **Text** -- Human-readable format for development:
  ```
  2026-02-20 10:30:00 [INFO] malwar.scanner.pipeline: Scan abc123 complete: ...
  ```

Configure with `MALWAR_LOG_FORMAT=json` or `MALWAR_LOG_FORMAT=text`.

**Sensitive data redaction:** API keys and tokens in log messages are automatically redacted. Patterns for Anthropic keys, OpenAI keys, AWS keys, GitHub tokens, and Bearer tokens are matched and truncated.

### Webhook Notifications

Configure webhook URLs to receive notifications when scans produce MALICIOUS or SUSPICIOUS verdicts:

```bash
MALWAR_WEBHOOK_URLS=https://hooks.slack.com/services/T00/B00/xxx,https://your-siem/webhook
```

Webhook payloads include scan_id, verdict, risk_score, finding_count, skill_name, and top 5 findings.

### CORS

The API server is configured with CORS allowing `http://localhost:3000` for the Vite development server. For production deployments where the frontend is served from the same origin, no CORS configuration is needed. If you need to allow additional origins, modify the CORS middleware in `src/malwar/api/app.py`.

### Health Checks

Use the health endpoints for monitoring and orchestration:

- `GET /api/v1/health` -- Returns `{"status": "ok"}` when the server is running. No authentication required.
- `GET /api/v1/ready` -- Returns `{"status": "ready", "database": "connected"}` when the database is accessible.

For Docker health checks:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1
```

### LLM Cost Management

Layer 3 (LLM analysis) calls the Anthropic API and incurs costs. Cost control measures:

1. **Risk threshold:** The LLM layer is automatically skipped when the risk score from prior layers is below `MALWAR_LLM_SKIP_BELOW_RISK` (default: 15). Clean skills never trigger an API call.

2. **Selective layers:** Use `--no-llm` in CLI or `"use_llm": false` in API requests to skip LLM analysis entirely.

3. **Layer selection:** Use `--layers rule_engine,threat_intel` to run only free detection layers.

4. **Model selection:** Configure `MALWAR_LLM_MODEL` to use a more cost-effective model if needed.

---

## CI/CD Integration

### GitHub Actions

The project includes a CI workflow (`.github/workflows/ci.yml`) with four jobs:

1. **Lint & Type Check** -- Runs `ruff check` and `mypy`
2. **Tests** -- Runs `pytest` with coverage (minimum 85%)
3. **Build Frontend** -- Builds the React frontend with `npm ci && npm run build`
4. **Build Package** -- Builds the Python package with `python -m build`

### SARIF Integration

malwar can output scan results in SARIF 2.1.0 format for integration with GitHub Code Scanning:

```bash
malwar scan path/to/SKILL.md --format sarif --output results.sarif.json
```

Upload the SARIF file as a GitHub code scanning result in your CI pipeline.

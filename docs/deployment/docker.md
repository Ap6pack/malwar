<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Docker & Compose Deployment

## Docker Compose (Recommended)

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

## Docker

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

### Health Checks

For Docker health checks:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1
```

---

## Production Considerations

### Reverse Proxy

In production, run malwar behind a reverse proxy (nginx, Caddy, or a cloud load balancer):

```nginx
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
```

!!! note
    SQLite supports concurrent reads but serializes writes. For high-throughput write workloads, consider running a single writer process with multiple reader processes.

### Rate Limiting

The built-in rate limiter operates per-IP, in-memory, per-process. For production rate limiting across instances, use a reverse proxy rate limiter or a Redis-backed solution.

Default: 60 requests per minute per IP. Configure with `MALWAR_RATE_LIMIT_RPM`.

---

## Database

### SQLite

malwar uses SQLite with WAL (Write-Ahead Logging) mode. The database is initialized automatically when the API server starts or when `malwar db init` is run.

### Database Location

| Deployment | Default Path | Recommended Path |
|---|---|---|
| Development | `./malwar.db` | `./malwar.db` |
| Docker | `/app/data/malwar.db` | Volume-mounted `/app/data/malwar.db` |
| Production | `./malwar.db` | `/var/lib/malwar/malwar.db` |

### Backup

```bash
# Stop writes first (or use SQLite backup API)
cp /var/lib/malwar/malwar.db /backups/malwar-$(date +%Y%m%d).db

# Zero-downtime backup with WAL mode
sqlite3 /var/lib/malwar/malwar.db ".backup /backups/malwar-$(date +%Y%m%d).db"
```

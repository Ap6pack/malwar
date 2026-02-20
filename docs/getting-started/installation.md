<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Installation

## Prerequisites

- Python 3.13 or later
- Node.js 20 (for building the frontend, optional)
- Docker (for containerized deployment, optional)

---

## Option 1: Install from Source

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

### Using Docker Compose (Recommended)

The simplest deployment method:

```bash
# Create .env with your configuration
cp .env.example .env
# Edit .env with your API keys

# Build and start
docker compose up -d
```

The API server and web dashboard are available at `http://localhost:8000`.

### Using Docker Directly

```bash
# Build the image
docker build -t malwar .

# Run the container
docker run -d \
  --name malwar \
  -p 8000:8000 \
  -v malwar-data:/app/data \
  -e MALWAR_API_KEYS="your-secret-key" \
  -e MALWAR_ANTHROPIC_API_KEY="sk-ant-your-key" \
  malwar
```

The multi-stage Dockerfile builds both the React frontend (Node.js) and the Python backend.

---

## Option 3: Kubernetes

Install with Helm:

```bash
helm install malwar deploy/helm/malwar/ \
  --set malwar.apiKeys[0]=your-secret-api-key \
  --set malwar.anthropicApiKey=sk-ant-your-key-here
```

See the full [Kubernetes Deployment Guide](../deployment/kubernetes.md) for detailed configuration.

---

## Verify Installation

After installing, verify everything works:

```bash
# Check the version
malwar version

# Initialize the database (if not already done)
malwar db init

# Run a quick scan
malwar scan path/to/SKILL.md

# Start the API server
malwar serve
```

---

## Next Steps

- [Quick Start Guide](quickstart.md) -- Scan your first file, start the API, use the SDK
- [CLI Reference](../guide/cli-reference.md) -- All commands with flags and examples
- [Configuration](../deployment/configuration.md) -- All environment variables

# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

# Stage 1: Install Python dependencies
FROM python:3.13-slim AS builder
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .

# Stage 2: Runtime image
FROM python:3.13-slim
WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 malwar && \
    useradd -u 1000 -g malwar -m -s /bin/sh malwar

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY src/ src/

# Create data directory for SQLite
RUN mkdir -p /data && chown malwar:malwar /data

# Switch to non-root user
USER malwar

EXPOSE 8000

ENV MALWAR_DB_PATH=/data/malwar.db

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

ENTRYPOINT ["uvicorn", "malwar.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

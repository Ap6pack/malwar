# Caching

malwar includes a caching layer for scan deduplication. When the same SKILL.md
content is scanned with the same detection layers, the cached result is returned
instead of re-running the full detection pipeline.

## How It Works

1. **Before scanning**: the pipeline computes a cache key from
   `SHA-256(content + sorted_layers + config_hash)` and checks the cache.
2. **Cache hit**: the previously stored `ScanResult` is returned immediately,
   skipping all detectors.
3. **Cache miss**: the full pipeline executes and the result is stored with a
   configurable TTL (default: 1 hour).

## Configuration

All settings use the `MALWAR_` environment variable prefix:

| Variable               | Default                      | Description                           |
|------------------------|------------------------------|---------------------------------------|
| `MALWAR_CACHE_BACKEND` | `memory`                     | Backend type: `memory` or `redis`     |
| `MALWAR_CACHE_TTL`     | `3600`                       | Time-to-live in seconds (1 hour)      |
| `MALWAR_REDIS_URL`     | `redis://localhost:6379/0`   | Redis connection URL (redis backend)  |

### In-Memory Backend (default)

The `memory` backend uses an in-process LRU cache with per-entry TTL. It
requires no external services and is suitable for single-process deployments.
Cached entries are lost when the process restarts.

### Redis Backend

The `redis` backend stores results in Redis, enabling cache sharing across
multiple API server workers or instances. It requires the optional `redis`
dependency:

```bash
pip install 'malwar[cache]'
```

If the `redis` package is not installed and `MALWAR_CACHE_BACKEND=redis` is
set, malwar gracefully degrades to the in-memory backend with a warning.

## CLI Commands

```bash
# Show cache statistics (hits, misses, hit rate, entry count)
malwar cache stats

# Clear all cached scan results
malwar cache clear
```

## API Endpoints

### POST `/api/v1/cache/clear`

Flush the scan result cache. Requires `config:manage` permission (admin only).

**Response:**
```json
{
  "cleared": 42,
  "message": "Cleared 42 cached entries"
}
```

### GET `/api/v1/cache/stats`

Show cache hit/miss statistics and current size. Requires `config:manage`
permission.

**Response:**
```json
{
  "hits": 150,
  "misses": 30,
  "total": 180,
  "hit_rate": 0.8333,
  "size": 25
}
```

## Cache Key Generation

The cache key is a SHA-256 hex digest computed from:

```
SHA-256(content + ",".join(sorted(layers)) + config_hash)
```

This ensures that:

- Different content produces different keys.
- Different layer configurations produce different keys.
- The same content scanned with layers in any order produces the same key.

# Role-Based Access Control (RBAC)

malwar supports role-based access control for API keys, allowing you to grant
fine-grained permissions to different API consumers.

## Roles

| Role       | Description                                   |
|------------|-----------------------------------------------|
| `admin`    | Full access to all operations                 |
| `analyst`  | Scan, read, manage signatures and campaigns   |
| `scanner`  | Create and read scans only                    |
| `readonly` | Read scan results and audit logs only         |

## Permissions

| Permission          | Description                          | Admin | Analyst | Scanner | ReadOnly |
|---------------------|--------------------------------------|:-----:|:-------:|:-------:|:--------:|
| `scan:create`       | Submit new scans                     |   X   |    X    |    X    |          |
| `scan:read`         | Read scan results and reports        |   X   |    X    |    X    |    X     |
| `signature:manage`  | Create, update, delete signatures    |   X   |    X    |         |          |
| `campaign:manage`   | View and manage campaigns            |   X   |    X    |         |          |
| `audit:read`        | Read audit log entries               |   X   |    X    |         |    X     |
| `config:manage`     | Manage system configuration          |   X   |         |         |          |
| `api_key:manage`    | Create, list, revoke API keys        |   X   |         |         |          |

## Managing API Keys

### CLI

```bash
# Create a key with a specific role
malwar keys create --role analyst --name "CI Scanner"

# List all keys
malwar keys list

# Revoke a key
malwar keys revoke <key_id>
```

### API Endpoints (admin-only)

```
POST   /api/v1/keys              Create a new key (returns raw key once)
GET    /api/v1/keys              List all keys (no raw values)
DELETE /api/v1/keys/{key_id}     Revoke a key
PUT    /api/v1/keys/{key_id}/role  Change a key's role
```

#### Create a key

```bash
curl -X POST http://localhost:8000/api/v1/keys \
  -H "X-API-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI Pipeline", "role": "scanner"}'
```

Response:
```json
{
  "id": "key-abc123def456",
  "name": "CI Pipeline",
  "role": "scanner",
  "raw_key": "mlw_...",
  "created_at": "2026-02-20T12:00:00+00:00"
}
```

**Important:** The `raw_key` is returned only once at creation time. Store it
securely.

#### List keys

```bash
curl http://localhost:8000/api/v1/keys \
  -H "X-API-Key: <admin-key>"
```

#### Revoke a key

```bash
curl -X DELETE http://localhost:8000/api/v1/keys/key-abc123def456 \
  -H "X-API-Key: <admin-key>"
```

#### Update a key's role

```bash
curl -X PUT http://localhost:8000/api/v1/keys/key-abc123def456/role \
  -H "X-API-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"role": "analyst"}'
```

## Backward Compatibility

- **No keys configured:** When neither environment variable keys
  (`MALWAR_API_KEYS`) nor database keys exist, authentication is disabled and
  all requests are treated as admin.
- **Environment variable keys:** Keys configured via `MALWAR_API_KEYS` are
  treated as admin keys for backward compatibility.
- **Database keys:** Keys created via `malwar keys create` or the
  `POST /api/v1/keys` endpoint are stored in the `api_keys` SQLite table.
  Only the SHA-256 hash of the key is persisted.

## Database Schema

The `api_keys` table (migration 004):

| Column      | Type    | Description                    |
|-------------|---------|--------------------------------|
| `id`        | TEXT    | Primary key (e.g. `key-abc...`)|
| `key_hash`  | TEXT    | SHA-256 hash of the raw key    |
| `name`      | TEXT    | Human-readable label           |
| `role`      | TEXT    | Role string (admin, etc.)      |
| `created_at`| TEXT    | ISO timestamp                  |
| `last_used` | TEXT    | ISO timestamp, nullable        |
| `is_active` | INTEGER | 1 = active, 0 = revoked       |

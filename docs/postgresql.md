# PostgreSQL Backend

malwar supports PostgreSQL as an alternative database backend for production deployments that require connection pooling, concurrent write scalability, and enterprise database tooling.

## Installation

Install the `postgres` extra to pull in the [asyncpg](https://github.com/MagicStack/asyncpg) driver:

```bash
pip install malwar[postgres]
```

## Configuration

Set two environment variables (or add them to your `.env` file):

| Variable | Description | Default |
|---|---|---|
| `MALWAR_DB_BACKEND` | `sqlite` or `postgres` | `sqlite` |
| `MALWAR_POSTGRES_URL` | PostgreSQL connection URI | *(empty)* |
| `MALWAR_POSTGRES_POOL_MIN` | Minimum pool connections | `2` |
| `MALWAR_POSTGRES_POOL_MAX` | Maximum pool connections | `10` |

Example `.env`:

```dotenv
MALWAR_DB_BACKEND=postgres
MALWAR_POSTGRES_URL=postgresql://malwar:secret@db.example.com:5432/malwar
MALWAR_POSTGRES_POOL_MIN=5
MALWAR_POSTGRES_POOL_MAX=20
```

## How It Works

### Backend abstraction

All database access goes through the `DatabaseBackend` abstract base class defined in `src/malwar/storage/backend.py`. Both `SQLiteBackend` and `PostgresDatabase` implement this interface, so repositories and application code remain backend-agnostic.

### Query parameter adaptation

SQLite uses `?` placeholders while PostgreSQL uses `$1, $2, ...` positional parameters. The `query_adapter` module transparently rewrites queries at execution time so that repository code can be written once with `?` markers.

### Connection pooling

The PostgreSQL backend wraps an `asyncpg.Pool` with configurable `min_size` / `max_size`. Connections are acquired per-query and returned to the pool automatically.

### Migrations

PostgreSQL has its own migration file (`pg_migrations.py`) that mirrors the SQLite schema but uses native PostgreSQL types:

| SQLite | PostgreSQL |
|---|---|
| `TEXT` (datetime) | `TIMESTAMP` |
| `TEXT` (bounded) | `VARCHAR(N)` |
| `INTEGER` (large) | `BIGINT` |
| `INTEGER` (boolean) | `BOOLEAN` |
| `REAL` | `DOUBLE PRECISION` |
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` |
| `INSERT OR IGNORE` | `INSERT ... ON CONFLICT DO NOTHING` |

Migrations are tracked in the same `schema_migrations` table and run automatically on startup when `MALWAR_AUTO_MIGRATE=true` (the default).

## Graceful Fallback

If `MALWAR_DB_BACKEND=postgres` is set but `asyncpg` is not installed, malwar raises a clear error message:

```
StorageError: PostgreSQL backend requires the 'asyncpg' package.
Install it with:  pip install malwar[postgres]
```

## Docker Compose Example

```yaml
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_DB: malwar
      POSTGRES_USER: malwar
      POSTGRES_PASSWORD: secret
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  malwar:
    build: .
    environment:
      MALWAR_DB_BACKEND: postgres
      MALWAR_POSTGRES_URL: postgresql://malwar:secret@db:5432/malwar
      MALWAR_POSTGRES_POOL_MIN: 2
      MALWAR_POSTGRES_POOL_MAX: 10
    depends_on:
      - db

volumes:
  pgdata:
```

## Architecture

```
init_backend()
  |
  +-- backend="sqlite" --> SQLiteBackend(aiosqlite.Connection)
  |                         - run_migrations() from migrations.py
  |
  +-- backend="postgres" -> PostgresDatabase(asyncpg.Pool)
                            - run_pg_migrations() from pg_migrations.py
```

Both backends implement `DatabaseBackend`:

- `execute(query, params)` -- single statement
- `executemany(query, params_seq)` -- bulk insert
- `fetch_one(query, params)` -- single row as dict
- `fetch_all(query, params)` -- all rows as list of dicts
- `commit()` -- explicit commit (no-op for PostgreSQL auto-commit)
- `close()` -- release connection/pool
- `backend_name` -- `"sqlite"` or `"postgres"`

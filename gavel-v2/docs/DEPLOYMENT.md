# Gavel v2 -- Deployment Operations

This document covers operational procedures for production Gavel deployments backed by Postgres + Alembic via docker-compose. It focuses on the two highest-stakes operator concerns: (1) backup and restore of the Postgres volume that holds governance chains, agents, and incidents, and (2) applying schema migrations and rolling back a Gavel release without corrupting state. All commands assume you are running from the repository root where `docker-compose.yml` lives and that `.env` has been populated from `.env.example` (see `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT`, `GAVEL_ENV`).

The compose stack has four services: `postgres` (data volume `gavel-pgdata`), `gavel-migrate` (one-shot `alembic upgrade head`), `gavel-gateway` (port 8100), and `gavel-proxy` (port 8200). Gavel's schema currently has two Alembic revisions under `gavel/db/migrations/versions/` (`0001_baseline.py`, `0002_enrollment_records.py`).

---

## Backup and Restore (Postgres)

### Taking a backup

Run `pg_dump` inside the `postgres` service, stream it out, and gzip it locally:

```bash
mkdir -p backups
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" \
  | gzip > "backups/gavel-$(date +%Y%m%d-%H%M%S).sql.gz"
```

The `-T` flag disables TTY allocation so the dump streams cleanly. Dumps are logical (SQL text) and portable across minor Postgres versions.

### Restoring a backup

Restores target a database that already exists (recreated on a fresh `postgres` container) and assume you are not yet running `gavel-gateway`:

```bash
gunzip < backups/gavel-YYYYMMDD-HHMMSS.sql.gz \
  | docker compose exec -T postgres \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

### Cadence

For production:

- **Nightly full dump** via the command above.
- **Every 6 hours** a secondary dump during business hours. This is a pragmatic substitute for continuous WAL archiving.
- **WAL archiving** is out of scope for this doc. If your RPO is under 6 hours, enable `archive_mode = on` and `archive_command` in `postgresql.conf` and ship WALs to object storage. Document that separately.

### Retention

- **30-day rolling** local copies under `backups/`.
- **90-day off-site** copies in encrypted object storage.
- Prune local backups older than 30 days; prune off-site older than 90.

### Off-site (encrypted)

Encrypt before upload. Either of:

```bash
# GPG symmetric
gpg --symmetric --cipher-algo AES256 \
  backups/gavel-20260414-020000.sql.gz

# or S3 with server-side AES256
aws s3 cp backups/gavel-20260414-020000.sql.gz \
  s3://your-bucket/gavel/ --sse AES256
```

Azure Blob equivalent: upload with a storage account that has encryption-at-rest enabled (default) and use a customer-managed key if your policy requires it.

### Verifying a backup (do this monthly)

Never trust a backup you have not restored:

```bash
docker run --rm -d --name gavel-restore-test \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e POSTGRES_USER="$POSTGRES_USER" \
  -e POSTGRES_DB="$POSTGRES_DB" \
  postgres:16-alpine

sleep 5
gunzip < backups/gavel-YYYYMMDD-HHMMSS.sql.gz \
  | docker exec -i gavel-restore-test \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"

docker exec gavel-restore-test psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -c "select count(*) from governance_chains;"

docker rm -f gavel-restore-test
```

If row counts are sensible and no errors surface, the backup is trustworthy.

### Disaster scenario: full DB loss

1. Stop the stack: `docker compose down` (do not remove volumes yet unless data is truly gone).
2. If `gavel-pgdata` is unrecoverable, remove it: `docker volume rm gavel-v2_gavel-pgdata`.
3. Bring Postgres up alone: `docker compose up -d postgres`.
4. Wait for the healthcheck: `docker compose ps postgres` shows `healthy`.
5. Restore from the latest verified dump (see Restoring a backup).
6. Run migrations: `docker compose run --rm gavel-migrate`. This applies `alembic upgrade head` against the restored DB; it is a no-op if the dump already contains `alembic_version` at head.
7. Start the app: `docker compose up -d gavel-gateway gavel-proxy`.
8. Smoke-check: `curl http://localhost:8100/status` and verify row counts on `governance_chains`, `agents`, and `incidents`.

---

## Migrations and Blue/Green Rollback

### Pre-deployment checklist

- Staging DB has been restored from a recent production dump.
- `alembic upgrade head` runs clean on staging.
- Both schemas (old and new) coexist: the previous Gavel image still passes its test suite against the new schema, and the new image passes against the old schema. This is the invariant that makes rollback safe.
- New migration files are reviewed -- no edits to existing revisions under `gavel/db/migrations/versions/`.

### Backward-compatible migration rules

Gavel uses docker-compose's `gavel-migrate` as a one-shot that runs before `gavel-gateway` starts. There is no runtime migration hook. That means the DB schema is always `>=` the app's expected schema -- and the app must tolerate that.

- **ADD COLUMN must be nullable or have a `server_default`.** Old code reading rows created before the new column still works, and new code reading rows from before the backfill gets a sane default.
- **NEVER DROP COLUMN in the same release that stops writing to it.** Split into two releases: release N stops writing to the column; release N+1 drops it. This keeps rollback from N+1 to N viable.
- **NEVER rename a column in a single migration.** Add the new column, dual-write from the app, backfill, switch reads, stop writing the old column (release N), then drop the old column in a later release (release N+1).
- **Index changes in production:** do not let Alembic emit a blocking `CREATE INDEX`. Use raw SQL with `CONCURRENTLY`:

  ```python
  from alembic import op

  def upgrade() -> None:
      op.execute("CREATE INDEX CONCURRENTLY ix_agents_purpose ON agents (purpose)")

  def downgrade() -> None:
      op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_agents_purpose")
  ```

  `CONCURRENTLY` statements cannot run inside a transaction, so either place them in their own revision or wrap with `op.get_bind().execution_options(isolation_level="AUTOCOMMIT")`.

### How `gavel-migrate` interacts with rollback

`gavel-migrate` runs `alembic upgrade head` and exits. `gavel-gateway` and `gavel-proxy` wait for it via `depends_on.condition: service_completed_successfully`. On rollback you must reverse the order: **downgrade the schema first, then deploy the older image.** If you deploy the older image against a forward schema, it will either crash on unknown columns or (worse) silently drop writes to new columns.

### Rollback procedure

1. **Stop the gateway and proxy, leave Postgres up:**

   ```bash
   docker compose stop gavel-gateway gavel-proxy
   ```

2. **Downgrade one revision:**

   ```bash
   docker compose run --rm gavel-migrate alembic downgrade -1
   ```

   For a multi-step rollback, target a specific revision: `alembic downgrade 0001_baseline`.

3. **Re-deploy the previous Gavel image.** Update the image tag in `docker-compose.yml` (or your registry alias) to the prior release:

   ```bash
   docker compose pull gavel-gateway gavel-proxy
   docker compose up -d gavel-gateway gavel-proxy
   ```

4. **Verify:**

   ```bash
   docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
     select 'governance_chains' as t, count(*) from governance_chains
     union all select 'agents', count(*) from agents
     union all select 'incidents', count(*) from incidents
     union all select 'chain_events', count(*) from chain_events;
   "
   curl -fsS http://localhost:8100/status
   ```

   Counts should match pre-deploy snapshots. A `/status` 200 response means the old image is healthy against the downgraded schema.

### What NOT to do

- **Never edit a previously-released migration file.** If a shipped migration has a bug, create a new revision that reverses or corrects the change. Editing history desyncs environments that already ran the old version.
- **Never skip `gavel-migrate`** by running `gavel-gateway` alone on a blank DB. The gateway assumes schema-at-head.
- **Never run `alembic downgrade base`** in production unless you intend to wipe all schema state. It drops every table.
- **Never downgrade across a migration that dropped a column** (see the rules above) -- the data is gone and downgrade cannot fabricate it.

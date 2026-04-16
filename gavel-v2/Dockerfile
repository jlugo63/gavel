# --- Gavel Governance Gateway ---
# Constitutional governance layer for autonomous AI agents
# https://github.com/jlugo63/constitutional-control-plane

FROM python:3.13-slim AS builder

LABEL org.opencontainers.image.title="Gavel Governance Gateway" \
      org.opencontainers.image.description="Constitutional governance for autonomous AI agents" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/jlugo63/constitutional-control-plane" \
      org.opencontainers.image.licenses="MIT"

ARG ADMIN_MODE=false

WORKDIR /app

# Install dependencies first (layer caching)
COPY pyproject.toml README.md alembic.ini ./
COPY gavel/ gavel/

RUN pip install --no-cache-dir -e ".[api,db]"

# Remove admin module when ADMIN_MODE is disabled
RUN if [ "$ADMIN_MODE" = "false" ] && [ -f gavel/admin.py ]; then \
        rm gavel/admin.py; \
    fi

# --- Runtime stage ---
FROM python:3.13-slim

LABEL org.opencontainers.image.title="Gavel Governance Gateway" \
      org.opencontainers.image.description="Constitutional governance for autonomous AI agents" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/jlugo63/constitutional-control-plane" \
      org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN groupadd --gid 1000 gavel && \
    useradd --uid 1000 --gid gavel --create-home gavel

WORKDIR /app

# Copy installed packages and app from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /usr/local/bin/alembic /usr/local/bin/alembic
COPY --from=builder /app /app

# Optional persistent data directory
RUN mkdir -p /app/data && chown -R gavel:gavel /app

USER gavel

EXPOSE 8100

CMD ["uvicorn", "gavel.gateway:app", "--host", "0.0.0.0", "--port", "8100"]

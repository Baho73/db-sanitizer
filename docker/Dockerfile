# Инструмент db-sanitizer: python + pg-клиент + greenmask (версия зафиксирована)
FROM greenmask/greenmask:v0.2.22 AS greenmask

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=greenmask /usr/bin/greenmask /usr/local/bin/greenmask
WORKDIR /app
RUN pip install --no-cache-dir faker "psycopg[binary]" pyyaml langgraph pytest
COPY pyproject.toml README.md ./
COPY sanitizer sanitizer
COPY tests tests
ENV PYTHONUTF8=1 GREENMASK_BIN=greenmask \
    DEMO_DSN=postgresql://demo:demo@demo-db:5432/demo \
    STAGING_DSN=postgresql://staging:staging@staging-db:5432/staging
CMD ["python", "-m", "sanitizer.cli", "--help"]

# Инструмент db-sanitizer: python + pg-клиент + greenmask (версия зафиксирована)
FROM greenmask/greenmask:v0.2.22 AS greenmask

FROM python:3.12-slim-trixie
# postgresql-client-17: мажор клиента обязан совпадать с сервером (postgres:17),
# иначе pg_dump/greenmask встанут с version mismatch. Безымянный
# postgresql-client из дистрибутива эту гарантию не давал (ревью 2).
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=greenmask /usr/bin/greenmask /usr/local/bin/greenmask
WORKDIR /app
# Версии зафиксированы: плавающие зависимости делают «воспроизводимый прогон»
# воспроизводимым только до следующего релиза любой из них.
RUN pip install --no-cache-dir       faker==40.13.0 "psycopg[binary]==3.3.4" pyyaml==6.0.1       langgraph==1.2.10 langgraph-checkpoint-sqlite==3.1.1 pytest==9.0.2
COPY pyproject.toml README.md ./
COPY sanitizer sanitizer
COPY tests tests
ENV PYTHONUTF8=1 GREENMASK_BIN=greenmask \
    DEMO_DSN=postgresql://demo:demo@demo-db:5432/demo \
    STAGING_DSN=postgresql://staging:staging@staging-db:5432/staging
CMD ["python", "-m", "sanitizer.cli", "--help"]

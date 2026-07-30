# Демо-цикл db-sanitizer. Запуск: make demo (из чистого клона).
COMPOSE = docker compose -f docker/docker-compose.yml
TOOL = $(COMPOSE) run --rm tool

.PHONY: up build seed plan run restore verify demo demo-dump test clean

up:
	$(COMPOSE) up -d demo-db staging-db

build:
	$(COMPOSE) build tool

seed: up
	$(TOOL) python -m sanitizer.cli demo-seed --dsn postgresql://demo:demo@demo-db:5432/demo

plan:
	$(TOOL) python -m sanitizer.cli plan --dsn postgresql://demo:demo@demo-db:5432/demo --auto-approve

run:
	$(TOOL) python -m sanitizer.cli run --dsn postgresql://demo:demo@demo-db:5432/demo

restore:
	$(TOOL) python -m sanitizer.cli restore --host staging-db --port 5432

verify:
	$(TOOL) python -m sanitizer.cli verify \
	  --src-dsn postgresql://demo:demo@demo-db:5432/demo \
	  --dst-dsn postgresql://staging:staging@staging-db:5432/staging

# полный цикл: посев -> план с гейтом -> два прохода -> restore -> верификация
demo: build seed plan run restore verify
	@echo "=== ДЕМО ЗАВЕРШЕНО: отчёт в out/verify-report.md ==="

# вход «дамп» из ТЗ: pg_dump демо-базы -> разворачивание во временную БД -> тот же конвейер
demo-dump: build seed
	$(TOOL) sh -c "pg_dump 'postgresql://demo:demo@demo-db:5432/demo' -n hr -Fd -f /app/out/src-dump \
	  && psql 'postgresql://staging:staging@staging-db:5432/staging' -q -c 'DROP DATABASE IF EXISTS intake' -c 'CREATE DATABASE intake' \
	  && pg_restore --no-owner -d 'postgresql://staging:staging@staging-db:5432/intake' /app/out/src-dump \
	  && python -m sanitizer.cli plan --dsn 'postgresql://staging:staging@staging-db:5432/intake' --auto-approve --plan out/plan-dump.yaml \
	  && python -m sanitizer.cli run --dsn 'postgresql://staging:staging@staging-db:5432/intake' --plan out/plan-dump.yaml --work out/dump-run \
	  && python -m sanitizer.cli restore --dump out/dump-run/dump --host staging-db --port 5432 \
	  && python -m sanitizer.cli verify --src-dsn 'postgresql://staging:staging@staging-db:5432/intake' \
	       --dst-dsn 'postgresql://staging:staging@staging-db:5432/staging' \
	       --plan out/plan-dump.yaml --work out/dump-run --report out/verify-dump.md"
	@echo "=== ВХОД-ДАМП ЗАВЕРШЁН: отчёт в out/verify-dump.md ==="

test:
	python -m pytest tests/unit -q

clean:
	$(COMPOSE) down -v
	rm -rf out

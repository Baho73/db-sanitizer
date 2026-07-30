# E2E (T-013): выполняется ВНУТРИ tool-контейнера после `sanitizer.cli run+restore`.
# Проверяет то, что юниты доказать не могут: воспроизводимость чек-сумм двух
# прогонов, несвязываемость получателей, fail-closed на дрейфе схемы.
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = os.environ.get("DEMO_DSN", "postgresql://demo:demo@demo-db:5432/demo")
DST = os.environ.get("STAGING_DSN", "postgresql://staging:staging@staging-db:5432/staging")
IN_TOOL = Path("/app").exists() and os.environ.get("GREENMASK_BIN")

pytestmark = pytest.mark.skipif(not IN_TOOL, reason="e2e runs inside tool container")


def run_cli(*args, env=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run([sys.executable, "-m", "sanitizer.cli", *args],
                          capture_output=True, text=True, env=e)


def test_verify_report_green():
    r = run_cli("verify", "--src-dsn", SRC, "--dst-dsn", DST)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "❌" not in r.stdout


def test_reproducibility_two_runs():
    """Тот же снапшот+соль+план -> совпадающие поколоночные чек-суммы."""
    r1 = run_cli("run", "--dsn", SRC, "--work", "out/rep1")
    r2 = run_cli("run", "--dsn", SRC, "--work", "out/rep2")
    assert r1.returncode == 0 and r2.returncode == 0, r1.stderr + r2.stderr
    d1 = Path("out/rep1/dump_path").read_text().strip()
    d2 = Path("out/rep2/dump_path").read_text().strip()
    files1 = sorted(p.name for p in Path(d1).glob("*.dat.gz"))
    import gzip
    import hashlib

    def digest(dump, names):
        h = hashlib.sha256()
        for n in names:
            with gzip.open(Path(dump) / n, "rb") as fh:
                h.update(fh.read())
        return h.hexdigest()

    assert digest(d1, files1) == digest(d2, files1)


def test_unlinkability_two_recipients():
    ra = run_cli("run", "--dsn", SRC, "--work", "out/recA", env={"RECIPIENT": "A"})
    rb = run_cli("run", "--dsn", SRC, "--work", "out/recB", env={"RECIPIENT": "B"})
    assert ra.returncode == 0 and rb.returncode == 0
    da = Path(Path("out/recA/dump_path").read_text().strip())
    db = Path(Path("out/recB/dump_path").read_text().strip())
    import gzip
    import hashlib

    def all_digest(d):
        h = hashlib.sha256()
        for p in sorted(d.glob("*.dat.gz")):
            with gzip.open(p, "rb") as fh:
                h.update(fh.read())
        return h.hexdigest()

    assert all_digest(da) != all_digest(db)


def test_schema_drift_fails_closed():
    import psycopg

    with psycopg.connect(SRC) as conn:
        conn.execute("ALTER TABLE hr.employees ADD COLUMN IF NOT EXISTS drift_col text")
        conn.commit()
    try:
        r = run_cli("plan", "--dsn", SRC, "--auto-approve", "--plan", "out/plan-drift.yaml",
                    "--llm-cache", "tests/fixtures/llm_votes_demo.json")
        # новая колонка не имеет голосов -> unresolved -> план отклонён с именем колонки
        assert r.returncode != 0
        assert "drift_col" in r.stdout
    finally:
        with psycopg.connect(SRC) as conn:
            conn.execute("ALTER TABLE hr.employees DROP COLUMN IF EXISTS drift_col")
            conn.commit()

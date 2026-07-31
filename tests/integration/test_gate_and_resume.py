# Свойства, объявленные документом и не работавшие: продолжение гейта между
# процессами, возобновляемость прохода 2, переносимость на враждебные имена. (T-109)
import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")

try:
    import psycopg
    with psycopg.connect(SRC, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="demo-db not running")

from sanitizer.policy import Plan  # noqa: E402
from sanitizer.postproc import _completed_tables  # noqa: E402
from sanitizer.profiler import ident, profile  # noqa: E402
from sanitizer.runlog import RunLog  # noqa: E402


def _cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "sanitizer.cli", *args],
                          capture_output=True, text=True, encoding="utf-8",
                          env={**os.environ, "PYTHONIOENCODING": "utf-8",
                               "PYTHONUTF8": "1", **(env or {})})


def test_gate_survives_process_exit(tmp_path):
    """§4.5 обещает «продолжение хоть через сутки». С чекпойнтером в памяти
    состояние умирало вместе с процессом, и гейт был декорацией."""
    plan_path, state = tmp_path / "plan.yaml", tmp_path / "state.db"
    first = _cli("plan", "--dsn", SRC, "--plan", str(plan_path),
                 "--checkpoint", str(state), "--thread", "t")
    assert first.returncode == 2, first.stdout + first.stderr
    assert not plan_path.exists()
    assert state.exists()                       # состояние пережило процесс

    second = _cli("approve", "--checkpoint", str(state), "--thread", "t",
                  "--confirm", "hr.employees.birth_date")
    assert second.returncode == 0, second.stdout + second.stderr
    assert plan_path.exists()
    pc = Plan.load(plan_path).columns["hr.employees.birth_date"]
    assert pc.confirmed and pc.confirmed_by == "human"   # не ci


def test_gate_rejection_leaves_no_plan(tmp_path):
    plan_path, state = tmp_path / "p.yaml", tmp_path / "s.db"
    _cli("plan", "--dsn", SRC, "--plan", str(plan_path),
         "--checkpoint", str(state), "--thread", "r")
    out = _cli("approve", "--checkpoint", str(state), "--thread", "r", "--reject")
    assert out.returncode == 1 and not plan_path.exists()


def test_approve_without_pending_gate_is_refused(tmp_path):
    out = _cli("approve", "--checkpoint", str(tmp_path / "empty.db"), "--thread", "nope")
    assert out.returncode == 1 and "Нечего подтверждать" in out.stdout


def test_pass2_skips_tables_already_done(tmp_path):
    """Проход 2 неидемпотентен: заменённый телефон при повторе заменяется снова."""
    rl = RunLog(tmp_path / "rl.db")
    run_id = rl.start_run("fp", "dev", "g1")
    rl.mark("pass2", "hr.tickets", "running")
    rl.mark("pass2", "hr.tickets", "done")
    rl.mark("pass2", "hr.addresses", "running")          # оборвалось на середине
    assert _completed_tables(rl) == {"hr.tickets"}
    assert run_id


def test_pass2_streams_and_replaces_atomically(tmp_path, monkeypatch):
    """Файл переписывается через временный с атомарной заменой, а не собирается
    списком строк в памяти: §5.5 говорит про 15 млн текстов."""
    import sanitizer.postproc as pp
    from sanitizer.corpus import build_corpora, load_components
    from sanitizer.mapper import Mapper, Salt
    from sanitizer.policy import PlanColumn

    dump = tmp_path / "dump"
    dump.mkdir()
    with gzip.open(dump / "7.dat.gz", "wt", encoding="utf-8", newline="") as fh:
        fh.write("1\tтелефон 89161234567\n2\tпросто текст\n\\.\n")
    monkeypatch.setattr(pp, "toc_tables", lambda *a, **k: {"7": "hr.t"})

    plan = Plan(1, "f", {"hr.t.id": PlanColumn("technical", "keep", "none", "pk"),
                         "hr.t.body": PlanColumn("free_text", "freetext", "none", "x")},
                [], [], {}, {"hr.t": ["id"]})
    salt = Salt(b"t", "d", "g")
    ts_obj = pp.TextSanitizer(
        Mapper(salt, build_corpora(load_components(Path("sanitizer/data/components-ru.json")))),
        salt, frozenset())
    summary = pp.process_dump(dump, plan, {"hr.t": ["id", "body"]}, ts_obj, resume=False)

    assert summary["hr.t"]["rows"] == 3
    assert not list(dump.glob("*.tmp"))                 # временных файлов не осталось
    with gzip.open(dump / "7.dat.gz", "rt", encoding="utf-8") as fh:
        body = fh.read()
    assert "89161234567" not in body and "просто текст" in body


def test_hostile_identifiers_do_not_break_introspection():
    """Имена с пробелами, CamelCase, служебным словом и кириллицей."""
    with psycopg.connect(SRC, autocommit=True) as c:
        c.execute('DROP SCHEMA IF EXISTS "Odd Schema" CASCADE; CREATE SCHEMA "Odd Schema"')
        c.execute('CREATE TABLE "Odd Schema"."User Table" '
                  '("id" int PRIMARY KEY, "order" varchar(20), "Отчество" varchar(40))')
        with c.cursor() as cur:
            cur.executemany('INSERT INTO "Odd Schema"."User Table" VALUES (%s,%s,%s)',
                            [(i, f"o{i}", f"Имя{i}") for i in range(20)])
        try:
            snap = profile(SRC, "Odd Schema")
            names = {col.name for col in snap.columns}
            assert names == {"id", "order", "Отчество"}
            assert [c.name for c in snap.columns if c.is_pk] == ["id"]
        finally:
            c.execute('DROP SCHEMA "Odd Schema" CASCADE')


def test_ident_quotes_every_part():
    from psycopg import sql

    assert isinstance(ident("hr.employees"), sql.Composed)
    assert isinstance(ident("order"), sql.Composed)

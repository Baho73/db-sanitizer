# Интеграционный тест M-POSTPROC: проход 2 против настоящего directory-дампа -
# разбор TOC, перезапись COPY-потоков, схема примечаний, восстановимость. (T-010)
import gzip
import os
import shutil
from pathlib import Path

import pytest

DSN = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")
GREENMASK = os.environ.get("GREENMASK_BIN", "greenmask")

try:
    import psycopg
    with psycopg.connect(DSN, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(
    not DB_UP or not shutil.which("pg_restore") or not shutil.which(GREENMASK),
    reason="нужны demo-db, pg_restore и greenmask (запускать в tool-контейнере)")

from sanitizer.corpus import build_corpora, load_components  # noqa: E402
from sanitizer.executor import run_pass1  # noqa: E402
from sanitizer.mapper import Mapper, Salt  # noqa: E402
from sanitizer.policy import Plan  # noqa: E402
from sanitizer.postproc import TextSanitizer, process_dump, toc_tables  # noqa: E402
from sanitizer.profiler import profile  # noqa: E402
from sanitizer.runlog import RunLog  # noqa: E402

PLAN = Path("out/sanitization-plan.yaml")
SALT = Salt(b"integration-master", "test", "g1")


@pytest.fixture(scope="module")
def fresh_dump(tmp_path_factory):
    """Настоящий дамп прохода 1 - вход для прохода 2."""
    if not PLAN.exists():
        pytest.skip("нет плана прогона")
    work = tmp_path_factory.mktemp("pass1")
    plan = Plan.load(PLAN)
    corpora = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))
    rl = RunLog(work / "rl.db")
    run_id = rl.start_run(plan.schema_fingerprint, "test", "g1")
    dump = run_pass1(plan, DSN, SALT, corpora, work, rl, run_id,
                     greenmask_bin=GREENMASK, plan_path=PLAN)
    snap = profile(DSN, "hr")
    order: dict[str, list[str]] = {}
    for c in snap.columns:
        order.setdefault(c.table, []).append(c.name)
    return plan, dump, order, corpora, rl, run_id


def test_toc_parsing_finds_tables(fresh_dump):
    _, dump, order, *_ = fresh_dump
    tables = set(toc_tables(dump).values())
    assert "hr.employees" in tables and "hr.addresses" in tables
    assert tables <= set(order)


def test_pass2_rewrites_only_freetext_tables(fresh_dump):
    plan, dump, order, corpora, rl, _ = fresh_dump
    before = {p.name: p.stat().st_size for p in dump.glob("*.dat.gz")}
    ts = TextSanitizer(Mapper(SALT, corpora), SALT, frozenset())
    summary = process_dump(dump, plan, order, ts, runlog=rl)
    expected = {c.rsplit(".", 1)[0] for c, pc in plan.columns.items()
                if pc.strategy == "freetext"}
    assert set(summary) == expected, (set(summary), expected)
    assert before   # дамп не пустой


def test_address_column_fully_replaced_in_dump(fresh_dump):
    """Ключевой регресс: в потоке адресов не остаётся фрагментов оригинала."""
    plan, dump, order, corpora, rl, _ = fresh_dump
    ts = TextSanitizer(Mapper(SALT, corpora), SALT, frozenset())
    process_dump(dump, plan, order, ts, runlog=rl)
    addr_file = next(k for k, v in toc_tables(dump).items() if v == "hr.addresses")
    with gzip.open(dump / f"{addr_file}.dat.gz", "rt", encoding="utf-8") as fh:
        body = fh.read()
    for leak in ("домофон", "спросить", "тверскя", "кв 12"):
        assert leak not in body, leak


def test_sanitization_schema_written(fresh_dump):
    plan, dump, order, corpora, rl, _ = fresh_dump
    ts = TextSanitizer(Mapper(SALT, corpora), SALT, frozenset())
    process_dump(dump, plan, order, ts, runlog=rl)
    sql = (dump / "sanitization.sql").read_text(encoding="utf-8")
    assert "CREATE SCHEMA IF NOT EXISTS sanitization" in sql
    assert "sanitization.summary" in sql


def test_dump_still_restorable_after_rewrite(fresh_dump):
    """Перезапись COPY-потоков не ломает архив: pg_restore -l читает его."""
    plan, dump, order, corpora, rl, _ = fresh_dump
    ts = TextSanitizer(Mapper(SALT, corpora), SALT, frozenset())
    process_dump(dump, plan, order, ts, runlog=rl)
    assert toc_tables(dump)          # pg_restore -l отработал без ошибки


def test_pass2_resumable_by_table(fresh_dump):
    """Проход 2 журналирует каждую таблицу - возобновляемость по таблицам."""
    plan, dump, order, corpora, rl, run_id = fresh_dump
    ts = TextSanitizer(Mapper(SALT, corpora), SALT, frozenset())
    process_dump(dump, plan, order, ts, runlog=rl)
    pass2 = {(t, st) for s, t, st, _ in rl.entries(run_id) if s == "pass2"}
    assert any(st == "done" for _, st in pass2)
    assert {t for t, st in pass2 if st == "done"} >= {"hr.addresses"}

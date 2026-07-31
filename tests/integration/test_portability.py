# Интеграционные тесты ранга 3: связь между колонками при перемешивании и
# работоспособность конвейера на схеме, отличной от демонстрационной hr. (T-107)
import json
import os
from pathlib import Path

import pytest

SRC = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")
DST = os.environ.get("STAGING_DSN", "postgresql://staging:staging@127.0.0.1:55433/staging")

try:
    import psycopg
    with psycopg.connect(SRC, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="demo-db not running")

from sanitizer.executor import _entity_column, _induced, prepare_artifacts  # noqa: E402
from sanitizer.mapper import Salt, gen_inn12  # noqa: E402

_S = Salt(b"portability", "t", "g")
from sanitizer.plan_graph import build_graph, run_planning  # noqa: E402
from sanitizer.policy import Plan, validate_plan  # noqa: E402
from sanitizer.profiler import profile  # noqa: E402

CORR = """
SELECT corr(e.salary, p.avg_amt) FROM hr.employees e
JOIN (SELECT employee_id, avg(amount) avg_amt FROM hr.payroll GROUP BY 1) p
  ON p.employee_id = e.id"""


def _corr(dsn: str) -> float:
    with psycopg.connect(dsn) as c:
        return c.execute(CORR).fetchone()[0]


def test_demo_db_has_hostile_cases():
    """Без ломающих случаев тесты измеряют подбор данных, а не поведение кода."""
    with psycopg.connect(SRC) as c:
        assert c.execute("SELECT count(*) FROM hr.contractors WHERE length(inn) = 10").fetchone()[0] > 0
        assert c.execute("SELECT count(*) FROM hr.employees WHERE tab_no > 999999").fetchone()[0] > 0
        assert c.execute("SELECT count(*) FROM hr.employees WHERE middle_name IS NULL").fetchone()[0] > 0
        assert c.execute(r"SELECT count(*) FROM hr.tickets WHERE position('\' in body_text) > 0"
                         ).fetchone()[0] > 0
        assert _corr(SRC) > 0.99          # связь «зарплата - начисления» есть в источнике


@pytest.mark.skipif(not Path("out/sanitization-plan.yaml").exists(), reason="нет прогона")
def test_linked_money_columns_keep_relation():
    """Разбор 4, находка 8: перемешивание по колонке рвало связь (1.00 -> 0.06)."""
    try:
        with psycopg.connect(DST) as c:
            c.execute("SELECT 1 FROM hr.payroll LIMIT 1")
    except Exception:
        pytest.skip("staging не развёрнут")
    assert _corr(DST) > 0.95


def test_entity_column_prefers_own_primary_key():
    plan = Plan(1, "f", {}, [
        ["hr.employees.position_id", "hr.positions.id"],
        ["hr.employees.id", "hr.payroll.employee_id"],
    ], [], {})
    # employees должна опознать СВОЙ ключ, а не первый попавшийся класс:
    # иначе оклады перемешивались по должности, а начисления - по сотруднику
    assert _entity_column(plan, "hr.employees", "id")[0] == "id"
    emp = _entity_column(plan, "hr.employees", "id")[1]
    pay = _entity_column(plan, "hr.payroll", "id")
    assert pay[0] == "employee_id" and pay[1] == emp      # одна группа на обе таблицы


def test_induced_permutation_stays_permutation():
    perm = {str(i): str((i * 7 + 3) % 100) for i in range(100)}
    present = {str(i) for i in range(0, 100, 2)}          # только чётные
    images = [_induced(perm, present, e) for e in sorted(present)]
    assert sorted(images) == sorted(present)             # биекция на подмножестве


def test_pipeline_works_on_foreign_schema(tmp_path):
    """Разбор 4, находка 15: вся правая половина V-модели существовала только
    для схемы hr. План строится и валидируется на произвольной схеме."""
    with psycopg.connect(SRC, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS crm CASCADE; CREATE SCHEMA crm")
        c.execute("CREATE TABLE crm.clients (id serial PRIMARY KEY, "
                  "surname varchar(60), phone varchar(20), inn varchar(12) UNIQUE)")
        with c.cursor() as cur:
            cur.executemany("INSERT INTO crm.clients (surname, phone, inn) VALUES (%s, %s, %s)",
                            [(f"Фамилия{i}", f"+7916123{i:04d}", gen_inn12(_S, f"crm{i}"))
                             for i in range(60)])
        votes = tmp_path / "votes.json"
        votes.write_text(json.dumps({
            "crm.clients.id": ["technical", 1.0],
            "crm.clients.surname": ["family", 0.9],
            "crm.clients.phone": ["phone", 0.9],
            "crm.clients.inn": ["inn", 0.9],
        }), encoding="utf-8")
        try:
            snap = profile(SRC, "crm")
            assert {c.qualified for c in snap.columns} == {
                "crm.clients.id", "crm.clients.surname", "crm.clients.phone", "crm.clients.inn"}
            out = run_planning(build_graph(), {
                "dsn": SRC, "schema": "crm", "llm_cache": str(votes),
                "plan_path": str(tmp_path / "plan.yaml"), "auto_approve": True,
            }, thread_id="crm")
            assert out["errors"] == []
            plan = Plan.load(tmp_path / "plan.yaml")
            assert plan.columns["crm.clients.phone"].strategy == "fake"
            assert validate_plan(plan, snap) == []
            # артефакты прохода 1 строятся без единого упоминания hr
            written = prepare_artifacts(plan, SRC, Salt(b"m", "d", "g"), {}, tmp_path / "art")
            assert (tmp_path / "art" / "salt.fingerprint").exists()
            assert all("hr." not in p.name for p in written)
        finally:
            c.execute("DROP SCHEMA crm CASCADE")

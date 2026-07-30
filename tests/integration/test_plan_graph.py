# Интеграционные тесты M-PLAN-GRAPH: полный конвейер на демо-базе,
# interrupt-гейт, автоаппрув, переиспользование плана. (T-008)
import json
import os
from pathlib import Path

import pytest

DSN = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")

try:
    import psycopg
    with psycopg.connect(DSN, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="demo-db not running")

from sanitizer.plan_graph import build_graph, resume_approved, run_planning  # noqa: E402
from sanitizer.policy import Plan  # noqa: E402

CONFIG = json.loads(Path("sanitizer/demo/plan-config.json").read_text(encoding="utf-8"))


def make_state(plan_path: Path, auto: bool) -> dict:
    return {
        "dsn": DSN, "schema": "hr",
        "llm_cache": "tests/fixtures/llm_votes_demo.json",
        "json_map": CONFIG["json_map"],
        "sensitive_categories": CONFIG["sensitive_categories"],
        "overrides": CONFIG["overrides"],
        "plan_path": str(plan_path),
        "auto_approve": auto,
    }


def test_gate_interrupts_then_resume(tmp_path):
    plan_path = tmp_path / "plan.yaml"
    graph = build_graph()
    result = run_planning(graph, make_state(plan_path, auto=False), thread_id="t1")
    assert "__interrupt__" in result            # граф остановился на гейте
    assert not plan_path.exists()               # финального плана ещё нет
    payload = result["__interrupt__"][0].value
    assert "plan_draft" in payload
    out = resume_approved(graph, thread_id="t1")
    assert out["errors"] == []
    assert plan_path.exists()                   # продолжение после аппрува дописало план


def test_auto_approve_produces_valid_plan(tmp_path):
    plan_path = tmp_path / "plan.yaml"
    out = run_planning(build_graph(), make_state(plan_path, auto=True), thread_id="t2")
    assert out["errors"] == []
    plan = Plan.load(plan_path)
    c = plan.columns
    assert c["hr.employees.last_name"].strategy == "fake"
    assert c["hr.employees.inn"].strategy == "generate"
    assert c["hr.addresses.addr_text"].strategy == "freetext"      # грязные адреса
    assert c["hr.contractors.city"].strategy == "fake"             # решение человека
    assert c["hr.positions.grade"].strategy == "shuffle"           # чувствительная категория
    assert c["hr.employees.attrs"].strategy == "jsonb"
    assert c["hr.employees.f_115"].strategy == "keep"              # решение человека
    # мягкая связь contractor_inn <-> contractors.inn попала на подтверждение
    assert any({"hr.contracts.contractor_inn", "hr.contractors.inn"} == set(x)
               for x in plan.soft_links_pending)


def test_plan_reuse_diff_empty(tmp_path):
    plan_path = tmp_path / "plan.yaml"
    run_planning(build_graph(), make_state(plan_path, auto=True), thread_id="t3")
    out2 = run_planning(build_graph(), make_state(plan_path, auto=True), thread_id="t4")
    assert out2["diff"] == {}                   # схема не менялась - доаппрува не требуется

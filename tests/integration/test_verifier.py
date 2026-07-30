# Интеграционный тест M-VERIFIER против пары демо/staging. Главное здесь -
# НЕГАТИВНЫЕ проверки: верификатор обязан падать на подсаженной утечке.
# Верификатор, который умеет только зеленеть, бесполезен - именно так утечка
# адресов однажды прошла мимо составной канарейки. (T-011)
import json
import os
from pathlib import Path

import pytest

SRC = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")
DST = os.environ.get("STAGING_DSN", "postgresql://staging:staging@127.0.0.1:55433/staging")

try:
    import psycopg
    with psycopg.connect(SRC, connect_timeout=3), psycopg.connect(DST, connect_timeout=3):
        with psycopg.connect(DST) as c:
            c.execute("SELECT 1 FROM hr.employees LIMIT 1")
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="нужны обе БД с прогнанной санитизацией")

from sanitizer.policy import Plan  # noqa: E402
from sanitizer.verifier import column_checksums, entropy, verify  # noqa: E402

PLAN = Path("out/sanitization-plan.yaml")
CANARIES = Path("out/canaries.json")


@pytest.fixture(scope="module")
def plan():
    if not PLAN.exists():
        pytest.skip("нет плана прогона")
    return Plan.load(PLAN)


def test_clean_copy_passes(plan):
    r = verify(SRC, DST, plan, CANARIES)
    failed = [c.name for c in r.checks if not c.passed]
    assert r.ok, f"провалены: {failed}"
    assert len(r.checks) >= 8


def test_planted_canary_leak_is_caught(plan):
    """Подсаживаем канарейку в копию - верификатор обязан покраснеть."""
    canary = json.loads(CANARIES.read_text(encoding="utf-8"))["values"]["dirty_addr_domofon"]
    with psycopg.connect(DST) as conn:
        conn.execute("UPDATE hr.addresses SET addr_text = addr_text || %s WHERE id = 1",
                     (" " + canary,))
        conn.commit()
    try:
        r = verify(SRC, DST, plan, CANARIES)
        assert not r.ok, "верификатор пропустил подсаженную канарейку"
        assert any("Канарейки в копии" in c.name and not c.passed for c in r.checks)
    finally:
        with psycopg.connect(DST) as conn:
            conn.execute("UPDATE hr.addresses SET addr_text = replace(addr_text, %s, '') "
                         "WHERE id = 1", (" " + canary,))
            conn.commit()


def test_planted_identity_leak_is_caught(plan):
    """Возвращаем в копию исходное значение ИНН - должна упасть fake(x)!=x."""
    with psycopg.connect(SRC) as s, psycopg.connect(DST) as d:
        orig = s.execute("SELECT inn FROM hr.employees WHERE id = 1").fetchone()[0]
        saved = d.execute("SELECT inn FROM hr.employees WHERE id = 1").fetchone()[0]
        d.execute("UPDATE hr.employees SET inn = %s WHERE id = 1", (orig,))
        d.commit()
    try:
        r = verify(SRC, DST, plan, CANARIES)
        assert not r.ok, "верификатор пропустил неизменённое исходное значение"
        assert any("fake(x)" in c.name and not c.passed for c in r.checks)
    finally:
        with psycopg.connect(DST) as d:
            d.execute("UPDATE hr.employees SET inn = %s WHERE id = 1", (saved,))
            d.commit()


def test_row_count_mismatch_is_caught(plan):
    """Удаляем строку из копии - должен упасть контроль объёма."""
    with psycopg.connect(DST) as d:
        row = d.execute("SELECT id, employee_id, action, ts FROM hr.audit_log "
                        "ORDER BY id DESC LIMIT 1").fetchone()
        d.execute("DELETE FROM hr.audit_log WHERE id = %s", (row[0],))
        d.commit()
    try:
        r = verify(SRC, DST, plan, CANARIES)
        assert not r.ok
        assert any("Объём" in c.name and not c.passed for c in r.checks)
    finally:
        with psycopg.connect(DST) as d:
            d.execute("INSERT INTO hr.audit_log (id, employee_id, action, ts) "
                      "VALUES (%s,%s,%s,%s)", row)
            d.commit()


def test_checksums_stable_across_calls(plan):
    a = column_checksums(DST, plan)
    b = column_checksums(DST, plan)
    assert a == b and len(a) > 10


def test_entropy_reacts_to_collapse():
    assert entropy([1000]) == 0.0
    assert entropy([500, 500]) > entropy([999, 1])

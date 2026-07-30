# Тесты M-DEMO-DB без БД: детерминизм генерации, канарейки на местах,
# враждебные случаи присутствуют, DDL согласован с генератором. (T-003)
from pathlib import Path

from sanitizer.demo.seed import CANARIES, SCALES, generate_rows

DDL = Path("sanitizer/demo/ddl.sql").read_text(encoding="utf-8")


def test_deterministic_by_seed():
    a, b = generate_rows("small", 42), generate_rows("small", 42)
    assert a.tables["hr.employees"] == b.tables["hr.employees"]
    assert generate_rows("small", 43).tables["hr.employees"] != a.tables["hr.employees"]


def test_all_ddl_tables_are_seeded():
    rows = generate_rows("small")
    ddl_tables = {line.split()[2] for line in DDL.splitlines() if line.startswith("CREATE TABLE")}
    assert ddl_tables == set(rows.tables)


def test_canaries_placed():
    rows = generate_rows("small")
    emp = rows.tables["hr.employees"][-1]
    assert (emp[2], emp[3], emp[4]) == tuple(CANARIES["fio_employee"].split())
    assert emp[6] == CANARIES["inn_soft_link"] and emp[11] == CANARIES["email_unique"]
    assert CANARIES["phone_jsonb"] in emp[14]                       # jsonb
    assert CANARIES["dirty_addr_tail"] in rows.tables["hr.addresses"][-1][2]
    assert rows.tables["hr.documents"][-1][3] == CANARIES["passport_doc"]
    assert rows.tables["hr.ticket_comments"][-1][3] == CANARIES["fio_phone_glued"]
    assert CANARIES["snils_in_text"] in rows.tables["hr.tickets"][-1][3]
    # мягкая связь: канареечный ИНН есть и в contractors
    assert any(c[2] == CANARIES["inn_soft_link"] for c in rows.tables["hr.contractors"])


def test_hostile_cases_present():
    rows = generate_rows("small")
    assert any("домофон" in a[2] for a in rows.tables["hr.addresses"])        # грязный адрес
    assert any("тел." in c[3] for c in rows.tables["hr.ticket_comments"])     # склейка
    assert all("," in c[5] for c in rows.tables["hr.contractors"])            # city с полным адресом
    assert "f_115" in DDL and "attrs" in DDL                                   # враждебные колонки


def test_scale_profiles():
    assert SCALES["small"][0] < SCALES["medium"][0] < SCALES["large"][0]
    n_emp = SCALES["small"][0]
    rows = generate_rows("small")
    assert len(rows.tables["hr.employees"]) == n_emp + 1  # + канарейка
    total = sum(len(v) for v in rows.tables.values())
    assert total > 50_000  # порядок 100 тыс. строк суммарно

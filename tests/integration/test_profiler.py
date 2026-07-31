# Интеграционные тесты M-PROFILER против демо-базы. (T-004)
import os

import pytest

DSN = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")

try:
    import psycopg
    with psycopg.connect(DSN, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="demo-db not running")

from sanitizer.profiler import addr_parse_ratio, profile  # noqa: E402


@pytest.fixture(scope="module")
def snap():
    return profile(DSN)


def test_tables_and_counts(snap):
    assert len(snap.row_counts) == 14
    assert snap.row_counts["hr.employees"] == 2001


def test_constraints_and_fks(snap):
    inn = snap.col("hr.employees.inn")
    assert inn.is_unique and not inn.nullable
    # композитный FK shipments -> contract_items
    comp = [f for f in snap.fks if f.src_table == "hr.shipments" and len(f.src_cols) == 2]
    assert comp and comp[0].dst_table == "hr.contract_items"


def test_stats_and_samples(snap):
    grade = snap.col("hr.positions.grade")
    assert grade.cardinality <= 7 and grade.samples
    assert snap.col("hr.employees.middle_name").null_frac >= 0.0


def test_jsonb_keys(snap):
    attrs = snap.col("hr.employees.attrs")
    assert "phone" in attrs.json_keys


def test_addr_ratio_flags_dirty_column(snap):
    dirty = snap.col("hr.addresses.addr_text")
    assert dirty.addr_parse_ratio is not None and dirty.addr_parse_ratio < 0.9
    assert snap.col("hr.contractors.city").addr_parse_ratio is not None  # имя врёт - метрика есть


def test_determinism(snap):
    again = profile(DSN)
    assert snap.to_json() == again.to_json()


def test_fk_named_like_foreign_pk_does_not_forge_pk():
    """Разбор 4, находка 2: имя ограничения уникально только внутри таблицы.
    FK, названный как PK соседней таблицы, помечал чужую колонку первичным ключом."""
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS fkname CASCADE; CREATE SCHEMA fkname")
        # a.email - обычная колонка; имя её таблицы приходит из table_constraints,
        # имя колонки email - из key_column_usage чужого ограничения-тёзки
        c.execute("CREATE TABLE fkname.a (id int CONSTRAINT x_key PRIMARY KEY, "
                  "email varchar(80) UNIQUE)")
        c.execute("CREATE TABLE fkname.b (email varchar(80) CONSTRAINT x_key "
                  "REFERENCES fkname.a(email))")
        c.execute("INSERT INTO fkname.a VALUES (1, 'user1@rusal.ru')")
        try:
            snap = profile(DSN, "fkname")
            assert not snap.col("fkname.a.email").is_pk
            assert snap.col("fkname.a.id").is_pk
        finally:
            c.execute("DROP SCHEMA fkname CASCADE")


def test_addr_parser_unit():
    assert addr_parse_ratio(["Тверская область, г. Ржев, ул. Садовая, д. 5"]) == 1.0
    assert addr_parse_ratio(["мск, тверскя 5 кв 12, спросить Марью, домофон 1234"]) == 0.0

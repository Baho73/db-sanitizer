# Тесты правок второго внешнего ревью в зоне M-VERIFIER (бандл C-REVIEW2-FIXES).
# Красные на коде до правки:
# - построчная fake(x)!=x была вакуумна для таблиц с трансформированным PK
#   (dst_vals.get(pk) всегда None - нарушение не засчитывалось никогда);
# - таблица без PK обрывала весь прогон верификации исключением;
# - паспорт не входил в wanted leak-проверки.
from sanitizer.policy import Plan, PlanColumn
from sanitizer import verifier as V


def _plan_pk_email() -> Plan:
    return Plan(1, "fp", {
        "hr.u.email": PlanColumn("email", "generate", "none", "ключ-ПДн"),
        "hr.u.name": PlanColumn("family", "fake", "corpus", "x"),
    }, [], [], {}, {"hr.u": ["email"]})


def test_multiset_overlap_basic():
    assert V._multiset_overlap({"a": 2}, {"b": 1}) == []
    assert V._multiset_overlap({"a": 2}, {"a": 1}) == ["a"]
    # NULL не трансформируется и законно встречается с обеих сторон
    assert V._multiset_overlap({None: 3}, {None: 1}) == []


def test_fake_ne_multiset_catches_untransformed_pk_value(monkeypatch):
    """PK трансформирован (generate - биекция): значение источника, доехавшее
    до копии, обязано сделать проверку красной. На старом коде построчная
    сверка по расходящемуся PK была зелёна при любом содержимом."""
    monkeypatch.setattr(V, "_col_multiset",
                        lambda cur, t, c: {"src@x.ru": 1} if cur == "SRC" else {"dst@y.ru": 1})
    r = V.VerifyReport()
    V._fake_ne_check(r, "SRC", "DST", _plan_pk_email(), {"hr.u": ["email"]})
    assert r.ok

    monkeypatch.setattr(V, "_col_multiset",
                        lambda cur, t, c: {"src@x.ru": 1})   # копия = источнику
    r = V.VerifyReport()
    V._fake_ne_check(r, "SRC", "DST", _plan_pk_email(), {"hr.u": ["email"]})
    assert not r.ok
    assert "hr.u.email" in r.checks[0].detail


def test_fake_ne_bijection_is_not_false_positive(monkeypatch):
    """Образ строки A, совпавший с исходником строки B (законно для биекции),
    построчной сверкой по PK записывался бы в нарушители - мультимножества
    такого ложного срабатывания не имеют."""
    src = {"a@x.ru": 1, "b@x.ru": 1}
    dst = {"c@x.ru": 1, "d@x.ru": 1}
    monkeypatch.setattr(V, "_col_multiset",
                        lambda cur, t, c: src if cur == "SRC" else dst)
    r = V.VerifyReport()
    V._fake_ne_check(r, "SRC", "DST", _plan_pk_email(), {"hr.u": ["email"]})
    assert r.ok


def test_table_without_pk_is_red_check_not_exception(monkeypatch):
    """Прежний _pk_expr бросал ValueError и обрывал ВЕСЬ прогон верификации:
    одна таблица без PK отменяла канарейки, FK и энтропию заодно."""
    r = V.VerifyReport()
    V._fake_ne_check(r, "SRC", "DST", _plan_pk_email(), {})   # pk_of пуст
    assert not r.ok
    assert any("первичн" in c.name.lower() and not c.passed for c in r.checks)


def test_fk_count_uses_nspname_not_regnamespace():
    """regnamespace::text на квотированной схеме («Odd Schema») молча не
    совпадает -> 0 == 0 -> проверка «FK восстановлены» зелёная, не проверив
    ничего. Тот же дефект в profiler._FK_SQL уже закрыт через nspname."""
    assert "nspname" in V._FK_COUNT
    assert "regnamespace" not in V._FK_COUNT


# --- паспорт в wanted leak-проверки (ревью 2, Н3) ------------------------------

def test_collect_passport_pairs():
    plan = Plan(1, "fp", {
        "hr.e.passport_series": PlanColumn("passport", "generate", "none", "x"),
        "hr.e.passport_number": PlanColumn("passport", "generate", "none", "x"),
        "hr.e.doc_number": PlanColumn("passport", "generate", "none", "x"),
    }, [], [], {})
    # пара собирается; одиночная doc_number без пары - не собирается (ложные
    # срабатывания на 4-6 цифрах недопустимы)
    assert V._collect_passport_pairs(plan) == {
        "hr.e": ("passport_series", "passport_number")}


def test_passport_wanted_values():
    got = V._passport_wanted_values(["4501123456", "4501 123456", "4501", None])
    assert got == {"4501123456"}          # недлинные и NULL-части отброшены

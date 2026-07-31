# Тесты правок второго внешнего ревью в зоне policy/executor/mapper/cmd_transformer
# (бандл C-REVIEW2-FIXES). Каждый тест красный на коде до правки:
# - покрытие колонок проверялось только при fingerprint-mismatch (обход валидации);
# - _shuffle_map не фильтровал NULL (миграция NULL в не-NULL строки);
# - Salt.version не входил в производную соль (мёртвое поле);
# - серия и номер паспорта заменялись раздельно (две замены одного документа);
# - исключения несли исходные значения/PK.
from pathlib import Path

import pytest

from sanitizer.cmd_transformer import RowTransformer
from sanitizer.corpus import build_corpora, load_components
from sanitizer.executor import _shuffle_map
from sanitizer.mapper import Salt, gen_digits_like, gen_int_like, normalize_digits
from sanitizer.policy import Plan, PlanColumn, schema_fingerprint, validate_plan
from sanitizer.profiler import ColumnInfo, Snapshot

S = Salt(b"review2", "d", "g")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))


# --- 6.4: обход валидации при сохранённом fingerprint --------------------------

def _snap() -> Snapshot:
    return Snapshot([
        ColumnInfo("hr.e", "id", "integer", None, False, False, True, 1000, 0.0, ["1"]),
        ColumnInfo("hr.e", "last_name", "character varying", 60, False, False, False,
                   50_000, 0.0, ["Синтетиков"]),
        ColumnInfo("hr.e", "phone", "character varying", 16, False, False, False,
                   50_000, 0.0, ["+79050000000"]),
    ], [], {"hr.e": 1000})


def test_column_removed_from_plan_fails_validation_with_same_fingerprint():
    """План с вручную удалённой колонкой невалиден даже при сохранённом
    fingerprint: отпечаток ловит дрейф схемы, покрытие - редактуру плана."""
    snap = _snap()
    plan = Plan(1, schema_fingerprint(snap), {
        "hr.e.id": PlanColumn("technical", "keep", "none", "pk"),
        "hr.e.last_name": PlanColumn("family", "fake", "corpus", "x"),
        "hr.e.phone": PlanColumn("phone", "fake", "corpus", "x"),
    }, [], [], {})
    assert not validate_plan(plan, snap)                  # полный план валиден
    del plan.columns["hr.e.phone"]                        # ручная редактура
    errors = validate_plan(plan, snap)
    assert any("hr.e.phone" in e and "not in plan" in e for e in errors)


# --- 6.8: NULL в shuffle-колонке ----------------------------------------------

class _FakeCursor:
    """Имитация psycopg-курсора: фиксирует SQL и применяет WHERE-фильтр так,
    как это сделала бы БД. Иначе тест проверял бы не запрос, а сам себя."""

    def __init__(self, rows):
        self.rows = rows
        self.sql_text = ""

    def execute(self, query):
        self.sql_text = str(query)

    def fetchall(self):
        if "IS NOT NULL" in self.sql_text:                # фильтр исполняет БД
            return [r for r in self.rows if r[2] is not None]
        return self.rows


def _shuffle_plan() -> Plan:
    return Plan(1, "f", {
        "hr.t.id": PlanColumn("technical", "keep", "none", "pk"),
        "hr.t.salary": PlanColumn("salary", "shuffle", "none", "x"),
    }, [], [], {}, {"hr.t": ["id"]})


def test_shuffle_map_filters_null_values():
    """NULL-строка не попадает в карту и не становится донором: ни одна
    не-NULL строка не получает {"d": null, "n": false}; доля NULL сохраняется.
    Мультимножество проверяется на равном числе строк на сущность - условие,
    при котором перестановка по сущности его сохраняет точно (_induced)."""
    rows = [("1", "e1", "100"), ("2", "e2", "200"), ("3", "e3", None),
            ("4", "e1", "100"), ("5", "e2", "200")]
    cur = _FakeCursor(rows)
    perms = {"hr.t.id": {"entity": {"hr.t": "id"},
                         "perm": {"e1": "e2", "e2": "e1", "e3": "e3"}}}
    out = _shuffle_map(cur, _shuffle_plan(), "hr.t", "salary", perms)
    assert "IS NOT NULL" in cur.sql_text
    assert None not in out.values()                       # NULL не мигрирует
    assert "3" not in out                                 # NULL-строка вне карты
    src = sorted(v for _, _, v in rows if v is not None)
    assert sorted(out.values()) == src                    # мультимножество сохранено


# --- 6.9: версия мастер-соли входит в производную соль -------------------------

def test_salt_version_changes_effective():
    """Ротация MASTER_SALT_VERSION без перевыпуска мастера обязана давать
    другую соль, иначе ротация - пустая операция (ревью 2, находка
    «Salt.version - мёртвое поле»)."""
    assert Salt(b"m", "r", "g", 1).effective != Salt(b"m", "r", "g", 2).effective
    assert Salt(b"m", "r", "g", 1).effective == Salt(b"m", "r", "g", 1).effective


# --- Н3 (структурная сторона): паспортная пара - единый 10-значный ключ --------

def _passport_plan(**extra) -> Plan:
    cols = {
        "hr.t.id": PlanColumn("technical", "keep", "none", "pk"),
        "hr.t.passport_series": PlanColumn("passport", "generate", "none", "x"),
        "hr.t.passport_number": PlanColumn("passport", "generate", "none", "x"),
        **extra,
    }
    return Plan(1, "f", cols, [], [], {}, {"hr.t": ["id"]})


def _row(**kv):
    return {k: {"d": v, "n": v is None} for k, v in kv.items()}


def test_passport_pair_replaced_as_single_10digit_key(tmp_path):
    """Серия+номер одной таблицы - ОДНА FPE-10 над 10 цифрами серия‖номер,
    разбиение 4+6; те же 10 цифр, что у текстового слоя («4501 123456»),
    - один идентификатор даёт один образ во всех представлениях."""
    t = RowTransformer(_passport_plan(), "hr.t", S, CORPORA, tmp_path)
    out = t.transform_row(_row(passport_series="4501", passport_number="123456"), "1")
    series, number = out["passport_series"]["d"], out["passport_number"]["d"]
    assert len(series) == 4 and len(number) == 6
    text_layer = gen_digits_like(S, "4501 123456")        # текстовый слой: FPE-10
    assert series + number == normalize_digits(text_layer)
    assert (series, number) != ("4501", "123456")
    # детерминизм: тот же документ в другой строке - тот же образ
    again = t.transform_row(_row(passport_series="45 01", passport_number="123456"), "2")
    assert (again["passport_series"]["d"], again["passport_number"]["d"]) == (series, number)


def test_passport_pair_is_injective(tmp_path):
    """Разные документы не склеиваются: пара образов уникальна на выборке."""
    t = RowTransformer(_passport_plan(), "hr.t", S, CORPORA, tmp_path)
    seen = set()
    for i in range(300):
        out = t.transform_row(_row(passport_series=f"45{i % 90:02d}",
                                   passport_number=f"{100000 + i:06d}"), "1")
        seen.add((out["passport_series"]["d"], out["passport_number"]["d"]))
    assert len(seen) == 300


def test_single_passport_column_keeps_per_column_behavior(tmp_path):
    """Колонка паспорта одна (или NULL во второй) - прежнее поколоночное
    поведение: gen_digits_like над значением самой колонки."""
    plan = Plan(1, "f", {
        "hr.t.passport_number": PlanColumn("passport", "generate", "none", "x"),
    }, [], [], {})
    t = RowTransformer(plan, "hr.t", S, CORPORA, tmp_path)
    out = t.transform_row(_row(passport_number="123456"), "1")
    assert out["passport_number"]["d"] == gen_digits_like(S, "123456")


def test_passport_pair_with_null_component_falls_back(tmp_path):
    """NULL в одной из колонок пары: NULL остаётся NULL, вторая колонка
    обрабатывается поколоночно (единый ключ собрать не из чего)."""
    t = RowTransformer(_passport_plan(), "hr.t", S, CORPORA, tmp_path)
    out = t.transform_row(_row(passport_series=None, passport_number="123456"), "1")
    assert out["passport_series"] == {"d": None, "n": True}
    assert out["passport_number"]["d"] == gen_digits_like(S, "123456")


# --- 6.12: исключения без исходных значений -----------------------------------

def test_direct_miss_exception_has_no_value(tmp_path):
    plan = Plan(1, "f", {"hr.t.org": PlanColumn("org_name", "direct", "direct", "x")},
                [], [], {})
    (tmp_path / "direct.hr.t.org.json").write_text('{"ООО Синтетика": "ООО Замена"}',
                                                   encoding="utf-8")
    t = RowTransformer(plan, "hr.t", S, CORPORA, tmp_path)
    with pytest.raises(KeyError) as exc:
        t.transform_row(_row(org="ЗАО Не-Должно-Утечь"), "1")
    msg = str(exc.value)
    assert "hr.t.org" in msg and "data drift" in msg      # колонка и код причины
    assert "Не-Должно-Утечь" not in msg                   # значения нет


def test_shuffle_miss_exception_has_no_pk(tmp_path):
    plan = Plan(1, "f", {"hr.t.salary": PlanColumn("salary", "shuffle", "none", "x")},
                [], [], {})
    (tmp_path / "shuffle.hr.t.salary.json").write_text('{"1": "50000"}', encoding="utf-8")
    t = RowTransformer(plan, "hr.t", S, CORPORA, tmp_path)
    with pytest.raises(KeyError) as exc:
        t.transform_row(_row(salary="150000"), "777")     # PK вне карты
    msg = str(exc.value)
    assert "hr.t.salary" in msg and "data drift" in msg
    assert "777" not in msg                               # ключа строки нет


def test_leading_zero_exception_has_no_value():
    with pytest.raises(ValueError) as exc:
        gen_int_like(S, "012345")
    assert "012345" not in str(exc.value)
    assert "ведущим нулём" in str(exc.value)              # код причины сохранён

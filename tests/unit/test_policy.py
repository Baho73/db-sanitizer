# Тесты M-POLICY: назначение, fail-closed валидация, дифф. (T-007)
from pathlib import Path

from sanitizer.classifier import ClassifiedColumn, SemType
from sanitizer.policy import Plan, PlanColumn, assign, plan_diff, schema_fingerprint, validate_plan
from sanitizer.profiler import ColumnInfo, ForeignKey, Snapshot


def make_snap():
    cols = [
        ColumnInfo("hr.e", "id", "integer", None, False, False, True, 1000, 0.0, ["1"]),
        ColumnInfo("hr.e", "last_name", "character varying", 60, False, False, False, 50_000, 0.0, ["Иванов"]),
        ColumnInfo("hr.e", "inn", "character varying", 12, False, True, False, 50_000, 0.0, ["770712345670"]),
        ColumnInfo("hr.e", "grade", "character varying", 8, False, False, False, 7, 0.0, ["J1"]),
        ColumnInfo("hr.e", "org", "character varying", 160, False, False, False, 60, 0.0, ["ООО Вектор"]),
        ColumnInfo("hr.e", "attrs", "jsonb", None, True, False, False, 900, 0.0, ["{}"], ["phone"]),
        ColumnInfo("hr.e", "addr", "character varying", 300, False, False, False, 900, 0.0, ["мск тверскя"],
                   [], 0.3),
        ColumnInfo("hr.c", "inn", "character varying", 12, False, False, False, 60, 0.0, ["770712345670"]),
    ]
    fks = [ForeignKey("hr.c", ("inn",), "hr.e", ("inn",))]
    return Snapshot(cols, fks, {"hr.e": 1000})


def classified():
    return [
        ClassifiedColumn("hr.e.id", SemType.TECHNICAL, 1.0, False, "pk"),
        ClassifiedColumn("hr.e.last_name", SemType.FAMILY, 0.9, False, "agree"),
        ClassifiedColumn("hr.e.inn", SemType.INN, 1.0, False, "agree"),
        ClassifiedColumn("hr.e.grade", SemType.CATEGORY, 0.8, False, "llm-only"),
        ClassifiedColumn("hr.e.org", SemType.ORG_NAME, 0.8, False, "llm-only"),
        ClassifiedColumn("hr.e.attrs", SemType.FREE_TEXT, 0.5, False, "jsonb"),
        ClassifiedColumn("hr.e.addr", SemType.ADDRESS, 0.7, False, "rules-strong"),
        ClassifiedColumn("hr.c.inn", SemType.INN, 1.0, False, "agree"),
    ]


def test_assign_strategies():
    plan = assign(classified(), make_snap(), sensitive_categories={"hr.e.grade"},
                  json_map={"hr.e.attrs": {"phone": "phone", "emergency": "fio_full"}},
                  llm_available=True)
    c = plan.columns
    assert c["hr.e.last_name"].strategy == "fake" and c["hr.e.last_name"].llm_mode == "corpus"
    assert c["hr.e.inn"].strategy == "generate"
    assert c["hr.e.grade"].strategy == "shuffle"           # чувствительная категория (§5.6)
    assert c["hr.e.org"].strategy == "direct"              # не-ПДн малой кардинальности (§3.1)
    assert c["hr.e.attrs"].strategy == "jsonb" and c["hr.e.attrs"].json_fields
    assert c["hr.e.addr"].strategy == "freetext"           # грязный адрес -> текст (§3.2)


def test_class_inherits_strategy():
    plan = assign(classified(), make_snap())
    assert ["hr.c.inn", "hr.e.inn"] in plan.classes
    assert plan.columns["hr.c.inn"].strategy == plan.columns["hr.e.inn"].strategy == "generate"


def test_validation_fail_closed():
    snap = make_snap()
    plan = assign(classified(), snap, json_map={"hr.e.attrs": {"phone": "phone"}})
    plan.columns["hr.e.grade"] = PlanColumn("category", "unresolved", "none", "x")
    plan.columns["hr.e.last_name"].strategy = "direct"     # ПДн в прямом режиме
    plan.columns["hr.e.addr"] = PlanColumn("address", "null", "none", "x", confirmed=False)
    errors = " ".join(validate_plan(plan, snap))
    assert "unresolved" in errors
    assert "direct mode is forbidden" in errors
    assert "requires human confirmation" in errors


def test_jsonb_without_map_is_unresolved():
    plan = assign(classified(), make_snap())               # без json_map
    assert plan.columns["hr.e.attrs"].strategy == "unresolved"
    assert any("attrs" in e for e in validate_plan(plan, make_snap()))


def test_fake_low_cardinality_blocked():
    snap = make_snap()
    plan = assign(classified(), snap, llm_available=True)

    def grade_errors():
        return [e for e in validate_plan(plan, snap)
                if e.startswith("hr.e.grade") and "frequency attack" in e]

    # категориальный тип с публично известным распределением - fake запрещён (§5.6)
    plan.columns["hr.e.grade"] = PlanColumn("category", "fake", "corpus", "forced")
    assert grade_errors()
    # для компонент ФИО той же кардинальности риск принят (§6.2) - не ошибка
    plan.columns["hr.e.grade"] = PlanColumn("family", "fake", "corpus", "forced")
    assert not grade_errors()
    # запрет снимается подтверждением на гейте, а не молча
    plan.columns["hr.e.grade"] = PlanColumn("category", "fake", "corpus", "forced",
                                            confirmed=True, confirmed_by="human")
    assert not grade_errors()


def test_schema_drift_detected():
    snap = make_snap()
    plan = assign(classified(), snap, json_map={"hr.e.attrs": {"phone": "phone"}})
    snap.columns.append(ColumnInfo("hr.e", "new_col", "text", None, True, False, False, 5, 0.0, []))
    errors = validate_plan(plan, snap)
    assert any("schema drift" in e and "new_col" in e for e in errors)


def test_dump_load_diff(tmp_path):
    snap = make_snap()
    plan = assign(classified(), snap, json_map={"hr.e.attrs": {"phone": "phone"}})
    p = tmp_path / "plan.yaml"
    plan.dump(p)
    loaded = Plan.load(p)
    assert loaded.columns.keys() == plan.columns.keys()
    loaded.columns["hr.e.org"].strategy = "keep"
    d = plan_diff(plan, loaded)
    assert d == {"hr.e.org": "changed"}
    # поля аудита решением не являются: подтверждение ставится после черновика,
    # и сравнение по нему давало бы «changed» на каждом прогоне
    loaded.columns["hr.e.org"].strategy = plan.columns["hr.e.org"].strategy
    loaded.columns["hr.e.org"].confirmed = True
    loaded.columns["hr.e.org"].confirmed_by = "human"
    assert plan_diff(plan, loaded) == {}

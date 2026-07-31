# Тесты путей утечки, найденных разбором 4 (ранг 1). Каждый тест падал бы
# на коде до правки: ключ-ПДн, ложный PK, неразмеченный ключ jsonb, подделка
# подтверждения. (T-104)
import json
from pathlib import Path

import pytest

from sanitizer.classifier import ClassifiedColumn, SemType, classify
from sanitizer.cmd_transformer import RowTransformer
from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import Salt
from sanitizer.plan_graph import apply_overrides
from sanitizer.policy import Plan, PlanColumn, assign, schema_fingerprint, validate_plan
from sanitizer.profiler import ColumnInfo, Snapshot

S = Salt(b"t", "d", "g")


def col(name, samples, dtype="character varying", pk=False, uniq=False, card=5000,
        table="hr.t", json_keys=()):
    return ColumnInfo(table, name, dtype, 120, True, uniq, pk, card, 0.0, samples,
                      list(json_keys), None)


# --- находка 1: первичный ключ не отменяет голоса классификатора ---

def test_pk_does_not_silence_voices():
    c = col("email", ["a@b.ru", "c.d@e.org", "x@y.ru"], pk=True)
    got = classify([c], {"hr.t.email": (SemType.EMAIL, 0.9)})[0]
    assert got.sem_type == SemType.EMAIL and got.reason == "agree"


def test_surrogate_pk_still_technical():
    c = col("id", ["1", "2", "3"], dtype="integer", pk=True)
    got = classify([c], {})[0]
    assert got.sem_type == SemType.TECHNICAL and not got.unresolved


def test_pii_key_gets_injective_strategy():
    snap = Snapshot([col("snils", ["112-233-445 95"], pk=True)], [], {"hr.t": 10})
    plan = assign([ClassifiedColumn("hr.t.snils", SemType.SNILS, 1.0, False, "agree")], snap)
    assert plan.columns["hr.t.snils"].strategy == "generate"


def test_pii_key_without_injective_replacement_is_unresolved():
    snap = Snapshot([col("last_name", ["Иванов"], uniq=True)], [], {"hr.t": 10})
    plan = assign([ClassifiedColumn("hr.t.last_name", SemType.FAMILY, 0.9, False, "agree")], snap)
    assert plan.columns["hr.t.last_name"].strategy == "unresolved"


def test_validate_rejects_pii_key_kept():
    snap = Snapshot([col("email", ["a@b.ru"], pk=True)], [], {"hr.t": 10})
    plan = Plan(1, schema_fingerprint(snap),
                {"hr.t.email": PlanColumn("email", "keep", "none", "human")}, [], [], {})
    assert any("ключ-ПДн" in e for e in validate_plan(plan, snap))


# --- находка 3Б: ключи jsonb входят в отпечаток схемы ---

def test_unmapped_jsonb_key_blocks_plan():
    c = col("attrs", ["{}"], dtype="jsonb", json_keys=["phone", "passport"])
    snap = Snapshot([c], [], {"hr.t": 10})
    plan = assign([ClassifiedColumn("hr.t.attrs", SemType.FREE_TEXT, 0.5, False, "jsonb")],
                  snap, json_map={"hr.t.attrs": {"phone": "phone"}})
    pc = plan.columns["hr.t.attrs"]
    assert pc.strategy == "unresolved" and "passport" in pc.reason


def test_new_jsonb_key_changes_fingerprint():
    before = Snapshot([col("attrs", ["{}"], dtype="jsonb", json_keys=["phone"])], [], {})
    after = Snapshot([col("attrs", ["{}"], dtype="jsonb", json_keys=["passport", "phone"])], [], {})
    assert schema_fingerprint(before) != schema_fingerprint(after)


# --- находка 3А: неразмеченный ключ jsonb не проходит насквозь ---

def _transformer(tmp_path, fields):
    plan = Plan(1, "f", {"hr.t.attrs": PlanColumn("free_text", "jsonb", "none", "x",
                                                  json_fields=fields)}, [], [], {})
    corpora = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))
    return RowTransformer(plan, "hr.t", S, corpora, tmp_path)


def test_unmapped_jsonb_key_is_not_passed_through(tmp_path):
    t = _transformer(tmp_path, {"phone": "phone", "note": "keep"})
    src = {"phone": "+79161234567", "note": "ok", "snils": "112-233-445 95"}
    out = t.transform_row({"attrs": {"d": json.dumps(src, ensure_ascii=False), "n": False}})
    got = json.loads(out["attrs"]["d"])
    assert got["snils"] is None and got["note"] == "ok" and got["phone"] != src["phone"]


# --- находка 4: подтверждение нельзя подделать конфигом ---

def _plan_with(strategy):
    return Plan(1, "f", {"hr.t.birth_date": PlanColumn("birth_date", strategy, "none", "x")},
                [], [], {})


def test_override_cannot_forge_confirmation():
    plan = _plan_with("generalize")
    with pytest.raises(ValueError, match="confirmed"):
        apply_overrides(plan, {"hr.t.birth_date": {"confirmed": True}})
    assert not plan.columns["hr.t.birth_date"].confirmed


def test_override_rejects_unknown_field_and_column():
    plan = _plan_with("keep")
    with pytest.raises(ValueError):
        apply_overrides(plan, {"hr.t.birth_date": {"whatever": 1}})
    with pytest.raises(ValueError):
        apply_overrides(plan, {"hr.t.nope": {"strategy": "keep"}})


def test_override_allows_markup_fields():
    plan = _plan_with("unresolved")
    apply_overrides(plan, {"hr.t.birth_date": {"strategy": "keep", "reason": "human: не ПДн"}})
    assert plan.columns["hr.t.birth_date"].strategy == "keep"


def test_confirmation_requires_author():
    snap = Snapshot([col("birth_date", ["1980-01-01"], dtype="date")], [], {})
    plan = _plan_with("generalize")
    plan.schema_fingerprint = schema_fingerprint(snap)
    plan.columns["hr.t.birth_date"].confirmed = True          # без confirmed_by
    assert any("confirmation" in e for e in validate_plan(plan, snap))
    plan.columns["hr.t.birth_date"].confirmed_by = "human"
    assert not any("confirmation" in e for e in validate_plan(plan, snap))

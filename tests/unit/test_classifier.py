# Тесты M-CLASSIFIER без БД и без LLM: правиловый голос, сведение голосов,
# unresolved на расхождении и общей слепоте. (T-005)
import json
from pathlib import Path

import pytest

from sanitizer.classifier import ClassifiedColumn, SemType, classify, llm_classify, rules_detect
from sanitizer.mapper import Salt, gen_inn12, gen_snils
from sanitizer.profiler import ColumnInfo

S = Salt(b"t", "d", "g")


def col(name, samples, table="hr.t", dtype="character varying", card=100, pk=False,
        addr_ratio=None, json_keys=()):
    c = ColumnInfo(table, name, dtype, 120, True, False, pk, card, 0.0, samples,
                   list(json_keys), addr_ratio)
    return c


def test_rules_checksummed_types():
    assert rules_detect(col("x", [gen_inn12(S, str(i)) for i in range(20)]))[0] == SemType.INN
    assert rules_detect(col("x", [gen_snils(S, str(i)) for i in range(20)]))[0] == SemType.SNILS
    assert rules_detect(col("x", ["+79051234567", "89161112233"]))[0] == SemType.PHONE
    assert rules_detect(col("x", ["a@b.ru", "c.d@e.org"]))[0] == SemType.EMAIL


def test_passport_needs_context_anchor():
    samples = ["4501 123456", "4402 654321"]
    assert rules_detect(col("doc_number", samples))[0] == SemType.PASSPORT
    # без якоря в имени - десятизначный формат не признаётся паспортом (§4.3)
    assert rules_detect(col("val3", samples))[0] != SemType.PASSPORT


def test_f115_is_blind_for_rules():
    st, conf = rules_detect(col("f_115", ["3", "5", "1"], dtype="integer"))
    assert st is None and conf == 0.0


def test_classify_agreement_and_conflict():
    cols = [col("inn", [gen_inn12(S, str(i)) for i in range(10)]),
            col("f_115", ["3", "5"], dtype="integer"),
            col("salary", ["55000", "72000"], dtype="numeric")]
    votes = {"hr.t.inn": (SemType.INN, 0.9),
             "hr.t.f_115": (None, 0.0),
             "hr.t.salary": (SemType.SALARY, 0.85)}
    out = {c.column: c for c in classify(cols, votes)}
    assert out["hr.t.inn"].sem_type == SemType.INN and not out["hr.t.inn"].unresolved
    assert out["hr.t.f_115"].unresolved and out["hr.t.f_115"].reason == "both-blind"
    assert out["hr.t.salary"].sem_type == SemType.SALARY  # llm-only с высокой уверенностью


def test_disagreement_goes_unresolved():
    c = col("code", ["+79051234567", "+79161112233"])
    votes = {"hr.t.code": (SemType.INN, 0.9)}  # LLM говорит ИНН, правила видят телефон
    res = classify([c], votes)[0]
    assert res.unresolved and "disagree" in res.reason


def test_pk_is_technical():
    c = col("id", ["1", "2"], dtype="integer", pk=True)
    assert classify([c], {})[0].sem_type == SemType.TECHNICAL


def test_llm_cache_required_offline(tmp_path):
    with pytest.raises(FileNotFoundError):
        llm_classify([], tmp_path / "absent.json")


def test_llm_cache_roundtrip(tmp_path):
    cache = tmp_path / "votes.json"
    cache.write_text(json.dumps({"hr.t.phone": ["phone", 0.9]}), encoding="utf-8")
    votes = llm_classify([], cache)
    assert votes["hr.t.phone"] == (SemType.PHONE, 0.9)

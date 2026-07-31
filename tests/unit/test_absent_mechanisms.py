# Тесты на механизмы, которых в коде физически не было (ранг 2 разбора 4):
# режим direct без LLM, валидатор корпусов вне конвейера, гейт публикации как
# печатная рекомендация, соль с публично известным умолчанием. (T-105)
import json
from pathlib import Path

import pytest

from sanitizer.classifier import ClassifiedColumn, SemType
from sanitizer.corpus import corpus_limits, validate_corpus
from sanitizer.mapper import Salt, salt_fingerprint
from sanitizer.policy import Plan, PlanColumn, assign, validate_plan
from sanitizer.profiler import ColumnInfo, Snapshot
from sanitizer.runlog import RunLog


def org_snap(card=60):
    return Snapshot([ColumnInfo("hr.c", "name", "character varying", 160, False, False,
                                False, card, 0.0, ["ООО Вектор"])], [], {"hr.c": card})


def org_classified():
    return [ClassifiedColumn("hr.c.name", SemType.ORG_NAME, 0.8, False, "llm-only")]


# --- находка 11: direct не назначается, когда механизма нет ---

def test_direct_map_stays_but_llm_mode_is_downgraded():
    """Карта 1:1 существует и без LLM; врать про её происхождение - нельзя."""
    pc = assign(org_classified(), org_snap()).columns["hr.c.name"]
    assert pc.strategy == "direct" and pc.llm_mode == "none"


def test_llm_mode_direct_when_provider_declared():
    pc = assign(org_classified(), org_snap(), llm_available=True).columns["hr.c.name"]
    assert pc.strategy == "direct" and pc.llm_mode == "direct"


def test_validate_rejects_llm_mode_without_provider():
    snap = org_snap()
    plan = assign(org_classified(), snap, llm_available=True)
    plan.params["llm_available"] = False          # поставщика убрали, план остался
    assert any("llm_mode direct" in e for e in validate_plan(plan, snap))


# --- находка 13: предел длины корпуса доезжает до валидатора ---

def test_corpus_limits_take_shortest_consumer():
    limits = corpus_limits({"hr.a.last_name": "family", "hr.b.surname": "family"},
                           {"hr.a.last_name": 60, "hr.b.surname": 12})
    assert limits["family"] == 12


def test_validate_corpus_catches_too_long_value():
    corpora = {"family": ["иванов", "распопов-краснопольский"]}
    assert any("exceeds column length" in p for p in validate_corpus(corpora, {"family": 12}))


def test_address_limits_cover_all_three_corpora():
    limits = corpus_limits({"hr.a.addr": "address"}, {"hr.a.addr": 40})
    assert limits == {"region": 40, "city": 40, "street": 40}


# --- находка 14: гейт публикации отказывает, а не советует ---

def _runlog(tmp_path) -> tuple[RunLog, str]:
    rl = RunLog(tmp_path / "runlog.db")
    run_id = rl.start_run("fp", "dev", "g1")
    return rl, run_id


def test_publish_refuses_without_verification(tmp_path):
    from sanitizer.cli import cmd_publish

    rl, run_id = _runlog(tmp_path)
    rl.mark("pass1", "*", "done")
    rl.mark("pass2", "*", "done")               # verify не проводился
    (tmp_path / "run_id").write_text(run_id, encoding="utf-8")
    (tmp_path / "dump_path").write_text(str(tmp_path / "dump"), encoding="utf-8")
    a = type("A", (), {"work": str(tmp_path), "to": str(tmp_path / "pub")})()
    assert cmd_publish(a) == 1
    assert not (tmp_path / "pub").exists()      # каталог не создан вовсе


def test_publish_copies_dump_after_verification(tmp_path):
    from sanitizer.cli import cmd_publish

    rl, run_id = _runlog(tmp_path)
    for stage in ("pass1", "pass2", "verify"):
        rl.mark(stage, "*", "done")
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "toc.dat").write_bytes(b"x")
    (tmp_path / "run_id").write_text(run_id, encoding="utf-8")
    (tmp_path / "dump_path").write_text(str(dump), encoding="utf-8")
    a = type("A", (), {"work": str(tmp_path), "to": str(tmp_path / "pub")})()
    assert cmd_publish(a) == 0
    assert (tmp_path / "pub" / run_id / "toc.dat").exists()
    assert cmd_publish(a) == 1                  # повторная публикация не перезаписывает


# --- соль: молчаливого публично известного умолчания больше нет ---

def test_salt_required(monkeypatch):
    from sanitizer.cli import _salt

    monkeypatch.delenv("MASTER_SALT", raising=False)
    with pytest.raises(SystemExit, match="MASTER_SALT"):
        _salt()
    monkeypatch.setenv("MASTER_SALT", "s")
    assert _salt().master == b"s"


def test_salt_fingerprint_separates_recipients():
    a = salt_fingerprint(Salt(b"m", "r1", "g1"))
    b = salt_fingerprint(Salt(b"m", "r2", "g1"))
    assert a != b and len(a) == 16 and a == salt_fingerprint(Salt(b"m", "r1", "g1"))

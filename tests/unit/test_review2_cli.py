# Тесты правок второго внешнего ревью в зоне M-CLI / M-RUNLOG / M-PLAN-GRAPH
# (бандл C-REVIEW2-FIXES). Красные на коде до правки:
# - перезапуск CLI порождал новый run_id, и resume прохода 2 был мёртв;
# - publishable удовлетворялся журналу с единственной строкой verify=done
#   и не замечал verify чужим планом/солью;
# - approve не был привязан к показанному черновику;
# - verify/publish без run_id падали traceback'ом.
import pytest

from sanitizer.cli import _read_run_file, _resume_or_start_run
from sanitizer.mapper import Salt
from sanitizer.plan_graph import gate_payload
from sanitizer.policy import Plan, PlanColumn
from sanitizer.runlog import RunLog

SALT = Salt(b"review2", "dev", "g1", 3)
PLAN = Plan(1, "fp-1", {"hr.t.id": PlanColumn("technical", "keep", "none", "pk")},
            [], [], {}, {"hr.t": ["id"]})


def _rl(tmp_path) -> RunLog:
    return RunLog(tmp_path / "runlog.db")


# --- run_id: возобновление прерванного прогона (ревью 2, Н1) -------------------

def test_interrupted_run_is_resumed_with_same_run_id(tmp_path):
    rl = _rl(tmp_path)
    rid = rl.start_run(PLAN.schema_fingerprint, SALT.recipient, SALT.generation,
                       master_salt_version=SALT.version)
    rl.mark("pass1", "*", "done")
    (tmp_path / "run_id").write_text(rid, encoding="utf-8")
    # На старом коде здесь порождался НОВЫЙ run_id, и _completed_tables
    # прошлого прогона был пуст - проход 2 трансформировал таблицы второй раз.
    assert _resume_or_start_run(rl, tmp_path, PLAN, SALT) == rid


def test_completed_run_starts_fresh(tmp_path):
    rl = _rl(tmp_path)
    rid = rl.start_run(PLAN.schema_fingerprint, SALT.recipient, SALT.generation,
                       master_salt_version=SALT.version)
    for stage in ("pass1", "pass2", "verify"):
        rl.mark(stage, "*", "done")
    (tmp_path / "run_id").write_text(rid, encoding="utf-8")
    assert _resume_or_start_run(rl, tmp_path, PLAN, SALT) != rid


def test_interrupted_run_with_other_fingerprints_is_refused(tmp_path):
    rl = _rl(tmp_path)
    rid = rl.start_run("fp-ДРУГОЙ", SALT.recipient, SALT.generation,
                       master_salt_version=SALT.version)
    rl.mark("pass1", "*", "running")
    (tmp_path / "run_id").write_text(rid, encoding="utf-8")
    with pytest.raises(SystemExit, match="ДРУГИМИ отпечатками"):
        _resume_or_start_run(rl, tmp_path, PLAN, SALT)


# --- гейт публикации: полнота прогона и однородность метаданных (ревью 2, Н5) --

def test_verify_only_journal_does_not_publish(tmp_path):
    """Журнал с единственной строкой verify=done раньше открывал публикацию:
    pass1/pass2 не требовались."""
    rl = _rl(tmp_path)
    rid = rl.start_run("fp-1", "dev", "g1")
    rl.mark("verify", "*", "done")
    assert not rl.publishable(rid)


def test_full_run_publishes(tmp_path):
    rl = _rl(tmp_path)
    rid = rl.start_run("fp-1", "dev", "g1")
    rl.mark("pass1", "*", "done")
    rl.mark("pass2", "hr.notes", "done")
    rl.mark("verify", "*", "done")
    assert rl.publishable(rid)


def test_verify_with_other_salt_breaks_publishable(tmp_path):
    """verify, записанный с другой солью/получателем под тем же run_id, раньше
    был неотличим от честного. Однородность метаданных это всплывает."""
    rl = _rl(tmp_path)
    rid = rl.start_run("fp-1", "dev", "g1")
    rl.mark("pass1", "*", "done")
    rl.meta = {"run_id": rid, "plan_version": "fp-1", "master_salt_version": 9,
               "salt_generation": "g1", "recipient_id": "attacker",
               "corpus_version": "x", "cache_version": "x", "tool_version": "x"}
    rl.mark("verify", "*", "done")
    assert not rl.publishable(rid)
    assert rl.meta_mismatches(rid)


# --- approve: привязка к показанному черновику (ревью 2, Н4) -------------------

def test_gate_payload_carries_draft_hash(tmp_path):
    draft = tmp_path / "plan.draft.yaml"
    draft.write_text("columns: {}", encoding="utf-8")
    import hashlib

    payload = gate_payload({"plan_path": str(tmp_path / "plan.yaml")})
    assert payload["draft_sha256"] == hashlib.sha256(b"columns: {}").hexdigest()
    # подмена черновика после показа меняет хэш - approve такое отклонит
    draft.write_text("columns: {подменено: да}", encoding="utf-8")
    assert gate_payload({"plan_path": str(tmp_path / "plan.yaml")})["draft_sha256"] \
        != payload["draft_sha256"]


# --- UX fail-closed -------------------------------------------------------------

def test_missing_run_id_file_is_friendly_error(tmp_path):
    with pytest.raises(SystemExit, match="run"):
        _read_run_file(tmp_path, "run_id")

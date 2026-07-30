# Тесты M-EXECUTOR/cmd_transformer без Greenmask и БД: протокол, стратегии,
# конфиг, run_log. (T-009)
import json
from pathlib import Path

from sanitizer.corpus import build_corpora, load_components
from sanitizer.cmd_transformer import RowTransformer, transform_line
from sanitizer.executor import greenmask_config
from sanitizer.mapper import Salt, valid_inn
from sanitizer.policy import Plan, PlanColumn
from sanitizer.runlog import RunLog

SALT = Salt(b"m", "dev", "g1")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))


def make_plan(tmp_path: Path) -> Plan:
    cols = {
        "hr.e.id": PlanColumn("technical", "keep", "none", "pk"),
        "hr.e.last_name": PlanColumn("family", "fake", "corpus", "x"),
        "hr.e.first_name": PlanColumn("name", "fake", "corpus", "x"),
        "hr.e.middle_name": PlanColumn("patronymic", "fake", "corpus", "x"),
        "hr.e.inn": PlanColumn("inn", "generate", "none", "x"),
        "hr.e.birth_date": PlanColumn("birth_date", "generalize", "none", "x", confirmed=True),
        "hr.e.salary": PlanColumn("salary", "shuffle", "none", "x"),
        "hr.e.attrs": PlanColumn("free_text", "jsonb", "none", "x",
                                 json_fields={"phone": "phone", "emergency": "fio_full", "note": "keep"}),
        "hr.e.org": PlanColumn("org_name", "direct", "direct", "x"),
        "hr.e.note_text": PlanColumn("free_text", "freetext", "none", "x"),
    }
    art = tmp_path / "artifacts"
    art.mkdir()
    (art / "direct.hr.e.org.json").write_text(
        json.dumps({"ООО Ромашка": "ООО ВЕКТОР-ПРИМ"}, ensure_ascii=False), encoding="utf-8")
    (art / "shuffle.hr.e.salary.json").write_text(json.dumps({"1": "99999", "2": "11111"}), encoding="utf-8")
    return Plan(1, "fp", cols, [], [], {})


def row(**kv):
    return {k: {"d": v, "n": v is None} for k, v in kv.items()}


def make_t(tmp_path):
    return RowTransformer(make_plan(tmp_path), "hr.e", SALT, CORPORA, tmp_path / "artifacts")


def test_fio_consistent_within_row(tmp_path):
    t = make_t(tmp_path)
    out = t.transform_row(row(last_name="Петрова", first_name="Анна", middle_name="Ивановна"), "1")
    fam = out["last_name"]["d"]
    assert fam != "Петрова" and fam.endswith("а")          # род сохранён
    assert out["first_name"]["d"] in [n.capitalize() for n in CORPORA["name_f"]]


def test_strategies(tmp_path):
    t = make_t(tmp_path)
    out = t.transform_row(row(inn="770712345670", birth_date="1985-03-14", salary="150000",
                              org="ООО Ромашка", note_text="секретный текст"), "1")
    assert valid_inn(out["inn"]["d"]) and out["inn"]["d"] != "770712345670"
    assert out["birth_date"]["d"] == "1985-01-01"          # тип сохранён, огрубление
    assert out["salary"]["d"] == "99999"                    # shuffle по PK
    assert out["org"]["d"] == "ООО ВЕКТОР-ПРИМ"             # direct 1:1
    assert out["note_text"]["d"] == "секретный текст"       # freetext не трогается в проходе 1


def test_jsonb_fields(tmp_path):
    t = make_t(tmp_path)
    src = json.dumps({"phone": "+79991234567", "emergency": "Петров Иван Иванович", "note": "ok"},
                     ensure_ascii=False)
    data = json.loads(t.transform_row(row(attrs=src), "1")["attrs"]["d"])
    assert data["phone"].startswith("+7") and data["phone"] != "+79991234567"
    assert "Петров" not in data["emergency"] and data["note"] == "ok"


def test_null_passthrough_and_protocol(tmp_path):
    t = make_t(tmp_path)
    line = json.dumps({"id": {"d": "7", "n": False}, "inn": {"d": None, "n": True}})
    out = json.loads(transform_line(t, line, "id"))
    assert out["inn"]["n"] is True and out["id"]["d"] == "7"


def test_direct_miss_fails_closed(tmp_path):
    t = make_t(tmp_path)
    try:
        t.transform_row(row(org="ООО Новая"), "1")
        assert False, "data drift must raise"
    except KeyError:
        pass


def test_greenmask_config_shape(tmp_path):
    plan = make_plan(tmp_path)
    cfg = greenmask_config(plan, "postgresql://x", tmp_path / "d", tmp_path / "p.yaml",
                           tmp_path / "artifacts")
    [tr] = cfg["dump"]["transformation"]
    assert tr["schema"] == "hr" and tr["name"] == "e"
    params = tr["transformers"][0]["params"]
    assert params["driver"]["name"] == "json"
    names = [c["name"] for c in params["columns"]]
    assert "id" in names and "note_text" not in names      # freetext не в проходе 1
    assert params["columns"][0] == {"name": "id", "not_affected": True}


def test_runlog_publish_gate(tmp_path):
    rl = RunLog(tmp_path / "rl.db")
    run = rl.start_run("plan-1", "dev", "g1")
    rl.mark("pass1", "*", "done")
    assert not rl.publishable(run)                          # verify ещё не было
    rl.mark("pass2", "hr.tickets", "done")
    rl.mark("verify", "*", "running")
    assert not rl.publishable(run)
    rl.mark("verify", "*", "done")
    assert rl.publishable(run)

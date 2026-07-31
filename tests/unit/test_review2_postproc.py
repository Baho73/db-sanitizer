# Тесты правок второго внешнего ревью в зоне M-POSTPROC (бандл C-REVIEW2-FIXES).
# Каждый тест красный на коде до правки:
# - _copy_unescape не знал \b \f \v и восьмеричные \ooo (молчаливая порча);
# - toc_tables сворачивал квотированные имена и молча пропускал таблицы;
# - сверки покрытия freetext-таблиц не было вовсе;
# - resume решал по паре «журнал+summary», расходящейся при крахе.
import gzip
import json
from pathlib import Path

import pytest

from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import Mapper, Salt
from sanitizer.policy import Plan, PlanColumn
from sanitizer import postproc as pp
from sanitizer.postproc import TextSanitizer, process_dump, toc_tables

SALT = Salt(b"review2", "dev", "g1")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))
NAMES = frozenset(CORPORA["name_m"] + CORPORA["name_f"])


def _ts() -> TextSanitizer:
    return TextSanitizer(Mapper(SALT, CORPORA), SALT, NAMES)


# --- unescape: полный алфавит COPY-эскейпов (ревью 2, §6.12) -------------------

def test_copy_unescape_control_chars_and_octal():
    assert pp._copy_unescape("a\\b\\f\\vend") == "a\b\f\vend"
    assert pp._copy_unescape("x\\101y") == "xAy"          # восьмеричный \101 = 'A'
    assert pp._copy_unescape("x\\07z") == "x\x07z"        # короткая форма


def test_copy_roundtrip_preserves_control_chars():
    src = "строка с\\b backspace и\\f подачей\\v и табом\\t"
    assert pp._copy_escape(pp._copy_unescape(src)) == src


# --- toc_tables: квотированные имена и fail-closed (ревью 2, Н2) ---------------

class _FakeCompleted:
    def __init__(self, stdout):
        self.stdout = stdout


def _fake_run(stdout):
    return lambda *a, **kw: _FakeCompleted(stdout)


def test_toc_parses_quoted_identifiers(monkeypatch, tmp_path):
    monkeypatch.setattr(pp.subprocess, "run", _fake_run(
        '7; 1 2 TABLE DATA "Odd Schema" "User Table" postgres\n'
        '8; 1 2 TABLE DATA hr notes postgres\n'
        '9; 1 2 TABLE DATA "Weird""Name" t postgres\n'))
    assert toc_tables(tmp_path) == {"7": "Odd Schema.User Table",
                                    "8": "hr.notes",
                                    "9": 'Weird"Name.t'}


def test_toc_unparsed_table_data_line_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(pp.subprocess, "run", _fake_run(
        "7; 1 2 TABLE DATA <- обрезанная строка\n"))
    with pytest.raises(ValueError, match="не разобрана"):
        toc_tables(tmp_path)


# --- process_dump: покрытие и resume по хэшам (ревью 2, Н1/Н2) -----------------

def _plan() -> Plan:
    return Plan(1, "fp", {
        "hr.notes.id": PlanColumn("technical", "keep", "none", "pk"),
        "hr.notes.body": PlanColumn("free_text", "freetext", "none", "x"),
    }, [], [], {}, {"hr.notes": ["id"]})


def _dump(tmp_path: Path, body: str = "звонил +7 905 123-45-67") -> Path:
    dump = tmp_path / "dump"
    dump.mkdir()
    with gzip.open(dump / "7.dat.gz", "wt", encoding="utf-8", newline="") as fh:
        fh.write(f"1\t{body}\n2\tобычный текст без сущностей\n\\.\n")
    return dump


def _read_rows(path: Path) -> list[str]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
        return fh.read().splitlines()


def test_freetext_table_missing_from_toc_is_refused(monkeypatch, tmp_path):
    _dump(tmp_path)
    monkeypatch.setattr(pp, "toc_tables", lambda *a, **kw: {"9": "hr.other"})
    with pytest.raises(ValueError, match="не найдены в TOC"):
        process_dump(tmp_path / "dump", _plan(), {"hr.notes": ["id", "body"]}, _ts())


def test_resume_by_hash_survives_process_restart(monkeypatch, tmp_path):
    """Второй запуск (уже без runlog прошлого прогона - новый процесс, новый
    run_id) обязан пропустить завершённую таблицу: файл байт-в-байт тот же.
    На коде до правки телефон уезжал в третье значение."""
    dump = _dump(tmp_path)
    monkeypatch.setattr(pp, "toc_tables", lambda *a, **kw: {"7": "hr.notes"})
    order = {"hr.notes": ["id", "body"]}
    process_dump(dump, _plan(), order, _ts())           # первый прогон
    after_first = (dump / "7.dat.gz").read_bytes()
    assert "+7 905 123-45-67" not in _read_rows(dump / "7.dat.gz")[0]
    process_dump(dump, _plan(), order, _ts())           # «перезапуск CLI»
    assert (dump / "7.dat.gz").read_bytes() == after_first


def test_crash_between_replace_and_state_write_is_refused(monkeypatch, tmp_path):
    """Крах посреди замены файла: state помнит только pre-хэш, файл изменился.
    Молчаливая повторная обработка дала бы двойную трансформацию - отказ."""
    dump = _dump(tmp_path)
    monkeypatch.setattr(pp, "toc_tables", lambda *a, **kw: {"7": "hr.notes"})
    order = {"hr.notes": ["id", "body"]}
    pre_hash = pp._sha256(dump / "7.dat.gz")
    process_dump(dump, _plan(), order, _ts())
    state = json.loads((dump / "sanitization-state.json").read_text(encoding="utf-8"))
    state["files"]["hr.notes"] = {"pre": pre_hash}      # post так и не записали
    (dump / "sanitization-state.json").write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ValueError, match="двойную трансформацию"):
        process_dump(dump, _plan(), order, _ts())


def test_unfinished_table_is_reprocessed_safely(monkeypatch, tmp_path):
    """Крах ДО замены файла (digest == pre): таблица обрабатывается заново,
    это безопасно - файл ещё исходный."""
    dump = _dump(tmp_path)
    monkeypatch.setattr(pp, "toc_tables", lambda *a, **kw: {"7": "hr.notes"})
    order = {"hr.notes": ["id", "body"]}
    pre_hash = pp._sha256(dump / "7.dat.gz")
    # state, как если бы крах случился сразу после записи pre-хэша
    (dump / "sanitization-state.json").write_text(json.dumps(
        {"notes": [], "summary": {}, "files": {"hr.notes": {"pre": pre_hash}}}),
        encoding="utf-8")
    summary = process_dump(dump, _plan(), order, _ts())
    assert summary["hr.notes"]["rows"] == 3
    assert "+7 905 123-45-67" not in _read_rows(dump / "7.dat.gz")[0]


# --- телефон «только с пробелами»: группировка вместо сплющенных цифр ----------

def test_space_only_phone_grouping_goes_to_phone_mapper():
    """«8 950 420 61 18» - группировка телефона X XXX XXX XX XX; прежний
    strip() стирал различие, и строки, проходящие КС СНИЛС, уезжали через
    gen_snils - расходясь со структурной колонкой (ревью 2, minor)."""
    ts = _ts()
    out, _ = ts.sanitize_text("контакт: 8 950 420 61 18, перезвонить")
    assert "8 950 420 61 18" not in out
    assert ts.mapper.phone("8 950 420 61 18") in out

# Находки шестого разбора: приоритет обработчиков в проходе 2, вердикт «не знаю»
# у роли NER, обнуление отчёта при возобновлении, слепота проверки к
# разделителям. Каждый тест красный на коде до правки. (T-113)
import gzip
import json
from pathlib import Path

import pytest

from sanitizer import llm as L
from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import Mapper, Salt, normalize_digits, normalize_phone
from sanitizer.policy import Plan, PlanColumn
from sanitizer.postproc import TextSanitizer
from sanitizer.runlog import RunLog
from sanitizer.verifier import _DIGIT_RUN_RE

S = Salt(b"r6", "d", "g")
M = Mapper(S, build_corpora(load_components(Path("sanitizer/data/components-ru.json"))))


def _ts(**kw) -> TextSanitizer:
    return TextSanitizer(M, S, frozenset(), **kw)


# --- Н1: якорь формы побеждает контрольную сумму ---

def test_phone_whose_digits_pass_inn_checksum_stays_a_phone():
    """У «+7 916 123-45-67» внутренние десять цифр - валидный ИНН. Распознаватель
    идентификаторов забирал участок раньше телефона, и номер уезжал через
    gen_inn10, расходясь с заменой того же номера в структурной колонке."""
    from sanitizer.mapper import valid_inn

    assert valid_inn("9161234567"), "предпосылка теста: хвост проходит КС ИНН"
    expected = M.phone("89161234567")
    for written in ("+7 916 123-45-67", "8 916 123-45-67", "+7 (916) 123-45-67",
                    "+79161234567"):
        got, _ = _ts().sanitize_text(f"тел {written}")
        assert normalize_phone(got.split(" ", 1)[1]) == normalize_phone(expected), written


def test_passport_shape_stays_passport():
    from sanitizer.mapper import gen_digits_like

    src = "4509 123456"
    got, _ = _ts().sanitize_text(f"паспорт {src}")
    assert got.split(" ", 1)[1] == gen_digits_like(S, src)


# --- Н2: неразобранный ответ модели - это «не знаю», а не «нет» ---

@pytest.mark.parametrize("verdict,expect_notes", [
    (None, ["low_confidence_ner"]),        # модель ответила невнятно
    (True, []),                            # модель уверена - замена
    (False, []),                           # модель уверена - оставить
])
def test_unparseable_model_answer_is_recorded_as_degradation(verdict, expect_notes):
    ts = _ts(llm=lambda fragment: verdict)
    _, notes = ts.sanitize_text("Заявку принял Аглая Востросаблина, перезвонить")
    assert notes == expect_notes


def test_ner_verdict_returns_none_on_unparseable_answer():
    class Fake(L.LLMClient):
        def __init__(self, reply):
            super().__init__("ollama", "m", "http://127.0.0.1:11434")
            self._r = reply

        def chat(self, prompt, system="", role=""):
            return self._r

    assert L.ner_verdict(Fake("да"), "Иванов Пётр") is True
    assert L.ner_verdict(Fake("нет"), "станок") is False
    assert L.ner_verdict(Fake("Затрудняюсь ответить"), "Иванов Пётр") is None
    assert L.ner_verdict(Fake(""), "Иванов Пётр") is None


def test_ner_acceptance_rejects_model_that_denies_names():
    class Denier(L.LLMClient):
        def __init__(self):
            super().__init__("ollama", "плохая", "http://127.0.0.1:11434")

        def chat(self, prompt, system="", role=""):
            return "нет"

    ok, report = L.ner_acceptance(Denier())
    assert not ok and "/10" in report


# --- Н3: возобновление не обнуляет отчёт о деградациях ---

def test_resume_keeps_previous_notes(tmp_path, monkeypatch):
    import sanitizer.postproc as pp

    dump = tmp_path / "dump"
    dump.mkdir()
    with gzip.open(dump / "7.dat.gz", "wt", encoding="utf-8", newline="") as fh:
        fh.write("1\tпередать Зюкозавру Хтоническому пакет\n2\tтекст\n\\.\n")
    monkeypatch.setattr(pp, "toc_tables", lambda *a, **k: {"7": "hr.t"})
    plan = Plan(1, "f", {"hr.t.id": PlanColumn("technical", "keep", "none", "pk"),
                         "hr.t.body": PlanColumn("free_text", "freetext", "none", "x")},
                [], [], {}, {"hr.t": ["id"]})
    rl = RunLog(tmp_path / "rl.db")
    rl.start_run("fp", "dev", "g1")

    first = pp.process_dump(dump, plan, {"hr.t": ["id", "body"]}, _ts(), runlog=rl, resume=False)
    sql_first = (dump / "sanitization.sql").read_text(encoding="utf-8")
    second = pp.process_dump(dump, plan, {"hr.t": ["id", "body"]}, _ts(), runlog=rl, resume=True)
    sql_second = (dump / "sanitization.sql").read_text(encoding="utf-8")

    assert first["hr.t"]["degraded"] >= 1
    assert second["hr.t"] == first["hr.t"]          # итоги не обнулились
    assert sql_first.count("sanitization.notes VALUES") == \
           sql_second.count("sanitization.notes VALUES")


# --- Н4: проверка утечки шире прохода 2 ---

@pytest.mark.parametrize("written", [
    "09085653089", "090-856-530 89", "090.856.530.89",
    "090/856/530 89", "(090) 856-530-89",
])
def test_leak_check_sees_every_separator_style(written):
    """Контролёр, делящий алфавит разделителей с подконтрольным, слеп там же."""
    hits = [m for m in _DIGIT_RUN_RE.findall(written)
            if normalize_digits(m) == "09085653089"]
    assert hits, written

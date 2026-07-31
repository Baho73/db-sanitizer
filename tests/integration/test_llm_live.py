# Живой прогон четырёх ролей на настоящей модели. Пропускается, если поставщик
# не настроен: демонстрация обязана идти без модели, по кэшу. (T-111)
import json
import os

import pytest

from sanitizer import llm as L
from sanitizer.classifier import SemType
from sanitizer.corpus import validate_corpus

CLIENT = None
try:
    CLIENT = L.from_env()
    if CLIENT is not None:
        CLIENT.chat("верни слово ок", role="ping")
except Exception:
    CLIENT = None

pytestmark = pytest.mark.skipif(
    CLIENT is None, reason="LLM_PROVIDER не настроен либо модель недоступна")


def test_role1_classifies_by_metadata_only():
    """Роль 1 видит только метаданные: имя, тип, статистику. Значений - нет."""
    meta = {
        "hr.employees.snils": {"type": "character varying", "len": 14, "card": 2001,
                               "null_frac": 0.0, "json_keys": []},
        "hr.employees.phone": {"type": "character varying", "len": 20, "card": 2001,
                               "null_frac": 0.0, "json_keys": []},
    }
    votes = L.classifier_ask(CLIENT, meta, [str(t) for t in SemType])
    assert votes, "модель не вернула ни одного голоса в опознаваемой форме"
    for column, (sem, conf) in votes.items():
        assert column in meta
        assert sem is None or sem in {str(t) for t in SemType}
        assert 0.0 <= float(conf) <= 1.0


PROBE = {
    "hr.employees.id": ("integer", None, 2001, "technical"),
    "hr.employees.dept_id": ("integer", None, 10, "technical"),
    "hr.employees.tab_no": ("integer", None, 2001, "person_id"),
    "hr.employees.hire_date": ("date", None, 1800, "technical"),
    "hr.employees.birth_date": ("date", None, 1900, "birth_date"),
    "hr.positions.grade": ("character varying", 8, 7, "category"),
    "hr.tickets.body_text": ("text", None, 3900, "free_text"),
}


def test_role1_quality_on_confusable_columns():
    """Замер качества второго голоса на путающих случаях. Без правил в промпте
    модель размечала ВСЕ суррогатные ключи как person_id - замерено на демо-схеме.
    Порог мягкий: голос модели не решает сам, расхождение уходит человеку."""
    meta = {col: {"type": t, "len": ln, "card": card, "null_frac": 0.0, "json_keys": []}
            for col, (t, ln, card, _) in PROBE.items()}
    votes = L.classifier_ask(CLIENT, meta, [str(t) for t in SemType])
    hits = sum(1 for col, (*_, expected) in PROBE.items()
               if votes.get(col, [None])[0] == expected)
    wrong = {col: votes.get(col, [None])[0] for col, (*_, e) in PROBE.items()
             if votes.get(col, [None])[0] not in (e, None)}
    assert hits >= 5, f"верно {hits}/{len(PROBE)}, ошибки: {wrong}"
    assert not wrong, f"уверенные ошибки опаснее воздержания: {wrong}"


def test_role2_generates_valid_corpus():
    """Роль 2 порождает материал замен с нуля и проходит валидатор корпусов."""
    values = L.corpus_generate(CLIENT, "family", 25)
    assert len(values) >= 10
    problems = validate_corpus({"family": sorted(set(values))})
    assert not problems, problems


def test_role3_direct_map_is_injective_and_changes_values():
    src = ["ООО Ромашка", "ООО Вектор Плюс", "АО Северный Путь"]
    mapping = L.direct_map(CLIENT, src)
    assert mapping, "модель не вернула ни одной замены"
    assert all(k in src and v != k for k, v in mapping.items())
    assert len(set(mapping.values())) == len(mapping)


@pytest.mark.skipif(CLIENT is not None and not CLIENT.sees_personal_data,
                    reason="свободный текст показывается только модели в контуре")
def test_role4_distinguishes_person_from_equipment():
    assert L.ner_verdict(CLIENT, "Иванов Пётр Сергеевич") is True
    assert L.ner_verdict(CLIENT, "Плановое обслуживание станка") is False


def test_pipeline_records_which_roles_were_used():
    before = len(CLIENT.calls)
    L.corpus_generate(CLIENT, "city", 10)
    assert CLIENT.calls[before:] == ["corpus:city"]

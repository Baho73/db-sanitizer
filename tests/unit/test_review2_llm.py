# Тесты правок бандла C-REVIEW2-FIXES по M-LLM (ревью 2, §6.11, п.1-3):
# direct_map терпим к ответу-массиву, уверенность классификатора валидируется,
# роль 3 уважает llm_mode аппрувнутого плана. Только синтетика, сети нет.
import json

import pytest

from sanitizer import llm as L
from sanitizer.cli import _direct_llm
from sanitizer.policy import Plan, PlanColumn

ALLOWED = ["org_name", "snils", "family"]
META = {"hr.t.org": {"type": "varchar"}, "hr.t.snils": {"type": "varchar"}}


class Fake(L.LLMClient):
    """Клиент с заданным ответом и счётчиком обращений к модели."""

    def __init__(self, reply):
        super().__init__(provider="ollama", model="m", base_url="http://127.0.0.1:11434")
        self._reply = reply

    def chat(self, prompt: str, system: str = "", role: str = "") -> str:
        self.calls.append(role or "chat")
        return self._reply if isinstance(self._reply, str) else json.dumps(self._reply)


def _plan(llm_mode: str) -> Plan:
    col = PlanColumn("org_name", "direct", llm_mode, "синтетика теста")
    return Plan(1, "fp", {"hr.c.name": col}, [], [], {})


# --- direct_map: ответ не обязан быть объектом (ревью 2, §6.11 п.1) ---

def test_direct_map_array_of_single_key_dicts():
    """(raw or {}).items() падал AttributeError на ответе-массиве."""
    got = L.direct_map(Fake([{"ООО Ромашка": "ООО Лаванда"},
                             {"ООО Вектор": "АО Сирень"}]),
                       ["ООО Ромашка", "ООО Вектор"])
    assert got == {"ООО Ромашка": "ООО Лаванда", "ООО Вектор": "АО Сирень"}


def test_direct_map_array_of_objects():
    got = L.direct_map(Fake([{"source": "ООО Ромашка", "replacement": "ООО Лаванда"}]),
                       ["ООО Ромашка"])
    assert got == {"ООО Ромашка": "ООО Лаванда"}


def test_direct_map_unparseable_items_are_skipped_not_raised():
    """Неразобранный ответ - пустая карта (достраивает corpus-fallback),
    а не AttributeError посреди исполнения."""
    got = L.direct_map(Fake(["не словарь", 42, []]), ["ООО Ромашка"])
    assert got == {}


# --- уверенность классификатора: валидация вместо float() вслепую (§6.11 п.2) ---

def test_non_numeric_confidence_drops_vote():
    """«высокая» вместо числа роняла планирование на float(conf)."""
    got = L.classifier_ask(Fake({"hr.t.snils": ["snils", "высокая"]}), META, ALLOWED)
    assert got == {}


def test_out_of_range_confidence_drops_vote():
    """conf=42 молча доминировал над честными голосами в [0,1]."""
    got = L.classifier_ask(Fake({"hr.t.snils": ["snils", 42]}), META, ALLOWED)
    assert got == {}


def test_valid_confidence_is_kept():
    got = L.classifier_ask(Fake({"hr.t.snils": ["snils", 0.7]}), META, ALLOWED)
    assert got == {"hr.t.snils": ["snils", 0.7]}


def test_none_type_keeps_zero_confidence_regardless():
    got = L.classifier_ask(Fake({"hr.t.snils": [None, 0.9]}), META, ALLOWED)
    assert got == {"hr.t.snils": [None, 0.0]}


# --- роль 3 уважает llm_mode аппрувнутого плана (§6.11 п.3) ---

def test_llm_mode_none_does_not_call_model():
    """План прошёл гейт с llm_mode=none (карта 1:1 из корпуса): исполнение
    обязано идти corpus-fallback даже при настроенном поставщике - иначе
    оно молча расходится с аппрувнутым планом."""
    client = Fake({"ООО Ромашка": "ООО Лаванда"})   # «env настроен»
    call = _direct_llm(client, _plan("none"))
    got = call("hr.c.name", ["ООО Ромашка"])
    assert got == {}
    assert client.calls == []       # к модели НЕ ходили


def test_llm_mode_direct_calls_model():
    client = Fake({"ООО Ромашка": "ООО Лаванда"})
    call = _direct_llm(client, _plan("direct"))
    got = call("hr.c.name", ["ООО Ромашка"])
    assert got == {"ООО Ромашка": "ООО Лаванда"}
    assert client.calls == ["direct"]


def test_no_client_means_no_call_regardless_of_plan():
    assert _direct_llm(None, _plan("direct")) is None

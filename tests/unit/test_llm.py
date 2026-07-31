# Тесты M-LLM без сети: разбор плавающих ответов модели, граница безопасности,
# фильтрация мусора. Живая модель - в tests/integration/test_llm_live.py. (T-110)
import json

import pytest

from sanitizer import llm as L
from sanitizer.classifier import SemType

ALLOWED = [str(t) for t in SemType]
META = {"hr.t.last_name": {"type": "varchar"}, "hr.t.snils": {"type": "varchar"}}


class Fake(L.LLMClient):
    """Клиент с заранее заданным ответом: сеть не нужна, форма ответа задаётся."""

    def __init__(self, reply, **kw):
        super().__init__(provider=kw.pop("provider", "ollama"), model="m",
                         base_url=kw.pop("base_url", "http://127.0.0.1:11434"), **kw)
        self._reply = reply

    def chat(self, prompt: str, system: str = "", role: str = "") -> str:
        self.calls.append(role or "chat")
        return self._reply if isinstance(self._reply, str) else json.dumps(self._reply)


# --- разбор ответа: модели отвечают в трёх разных формах ---

@pytest.mark.parametrize("reply", [
    {"hr.t.last_name": ["family", 0.9], "hr.t.snils": ["snils", 1.0]},
    [{"hr.t.last_name": ["family", 0.9]}, {"hr.t.snils": ["snils", 1.0]}],
    [{"column": "hr.t.last_name", "type": "family", "confidence": 0.9},
     {"column": "hr.t.snils", "type": "snils", "confidence": 1.0}],
])
def test_classifier_parses_every_shape(reply):
    got = L.classifier_ask(Fake(reply), META, ALLOWED)
    assert got == {"hr.t.last_name": ["family", 0.9], "hr.t.snils": ["snils", 1.0]}


def test_json_inside_prose_and_fences():
    reply = 'Вот ответ:\n```json\n{"hr.t.snils": ["snils", 1.0]}\n```\nГотово.'
    assert L.classifier_ask(Fake(reply), META, ALLOWED) == {"hr.t.snils": ["snils", 1.0]}


def test_thinking_block_is_stripped():
    reply = '<think>рассуждаю про колонки</think>{"hr.t.snils": ["snils", 1.0]}'
    assert L.classifier_ask(Fake(reply), META, ALLOWED) == {"hr.t.snils": ["snils", 1.0]}


def test_array_answer_is_not_cut_to_first_object():
    """Поиск «{» находил первый объект ВНУТРИ массива и терял остальные."""
    assert L._first_json('[{"a": [1,2]}, {"b": [3,4]}]') == [{"a": [1, 2]}, {"b": [3, 4]}]


# --- мусор от модели не проходит ---

def test_positional_answer_without_names_is_rejected():
    """Сопоставление по порядку разметило бы СНИЛС как фамилию."""
    client = Fake([["family", 0.9], ["snils", 1.0]])
    assert L.classifier_ask(client, META, ALLOWED) == {}
    assert client.calls == ["classify", "classify-retry"]     # одна попытка переспросить


def test_unknown_type_becomes_dont_know():
    got = L.classifier_ask(Fake({"hr.t.snils": ["галактика", 0.99]}), META, ALLOWED)
    assert got == {"hr.t.snils": [None, 0.0]}


def test_unknown_column_is_dropped():
    assert L.classifier_ask(Fake({"нет.такой.колонки": ["snils", 1.0]}), META, ALLOWED) == {}


def test_short_column_name_is_matched_by_tail():
    assert L.classifier_ask(Fake({"snils": ["snils", 1.0]}), META, ALLOWED) == \
        {"hr.t.snils": ["snils", 1.0]}


def test_ambiguous_tail_is_not_guessed():
    meta = {"hr.a.inn": {}, "hr.b.inn": {}}
    assert L.classifier_ask(Fake({"inn": ["inn", 1.0]}), meta, ALLOWED) == {}


def test_direct_map_filters_identity_and_foreign_keys():
    reply = {"ООО Ромашка": "ООО Лаванда", "ООО Вектор": "ООО Вектор", "чужое": "х"}
    got = L.direct_map(Fake(reply), ["ООО Ромашка", "ООО Вектор"])
    assert got == {"ООО Ромашка": "ООО Лаванда"}


# --- граница безопасности: живой текст только модели в контуре ---

def test_external_provider_refused_for_free_text():
    external = Fake("да", provider="openai", base_url="https://api.openai.com")
    assert not external.sees_personal_data
    with pytest.raises(L.LLMUnavailable, match="персональными данными"):
        L.ner_verdict(external, "Иванов Пётр")


@pytest.mark.parametrize("url,local", [
    ("http://127.0.0.1:11434", True),
    ("http://localhost:11434", True),
    ("http://ollama:11434", True),
    ("https://api.openai.com", False),
    ("https://api.deepseek.com/v1", False),
])
def test_locality_is_decided_by_host(url, local):
    assert Fake("x", base_url=url).sees_personal_data is local


def test_ner_verdict_reads_plain_answer():
    assert L.ner_verdict(Fake("Да."), "Иванов Пётр") is True
    assert L.ner_verdict(Fake("нет"), "Плановое обслуживание") is False


# --- отсутствие поставщика не ошибка ---

def test_no_provider_is_not_an_error(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert L.from_env() is None


def test_unknown_provider_is_refused(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "моямодель")
    with pytest.raises(L.LLMUnavailable, match="LLM_PROVIDER"):
        L.from_env()


def test_env_configures_client(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-x")
    monkeypatch.setenv("LLM_BASE_URL", "https://gate.example/")
    c = L.from_env()
    assert (c.model, c.base_url) == ("gpt-x", "https://gate.example")

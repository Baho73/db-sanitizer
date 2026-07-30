# Тесты M-CORPUS: загрузка фикстур, валидатор, кэш LLM без сети. (T-002)
import json
from pathlib import Path

import pytest

from sanitizer.corpus import build_corpora, llm_components, load_components, validate_corpus
from sanitizer.mapper import Mapper, Salt

FIXTURE = Path("sanitizer/data/components-ru.json")


def test_fixture_loads_and_validates():
    corpora = build_corpora(load_components(FIXTURE))
    assert validate_corpus(corpora) == []
    assert len(corpora["family"]) >= 30


def test_validator_catches_problems():
    bad = {
        "family": ["иванов", "иванов"],          # дубль
        "phone_code": ["12x"],                    # формат + меньше 2
        "name_m": ["ok-имя", "Q"],                # латиница/короткое
    }
    problems = validate_corpus(bad)
    assert any("duplicates" in p for p in problems)
    assert any("phone_code" in p for p in problems)
    assert any("name_m" in p for p in problems)


def test_length_limit_from_consumer_column():
    corpora = {"family": ["кузнецов", "верхнеколымскодлиннющев"]}
    assert validate_corpus(corpora, max_len={"family": 12}) != []


def test_llm_cache_roundtrip(tmp_path):
    cache = tmp_path / "c.json"
    calls = []

    def fake_llm(kind):
        calls.append(kind)
        return json.loads(FIXTURE.read_text(encoding="utf-8"))[kind]

    first = llm_components(cache, fake_llm)
    assert calls  # генерация была
    calls.clear()
    second = llm_components(cache)  # из кэша, без LLM
    assert second == first and not calls


def test_no_cache_no_llm_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        llm_components(tmp_path / "absent.json")


def test_corpora_feed_mapper():
    corpora = build_corpora(load_components(FIXTURE))
    m = Mapper(Salt(b"k", "dev", "g1"), corpora)
    f, n, p = m.fio("Петров", "Иван", "Иванович")
    assert f in corpora["family"] and n in corpora["name_m"] and p in corpora["patronymic_m"]

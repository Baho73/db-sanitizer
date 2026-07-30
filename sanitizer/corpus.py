# START_MODULE_CONTRACT
#   PURPOSE: Корпуса значений для fake-стратегии: комбинаторная сборка из взвешенных
#            компонент, детерминированный валидатор, интерфейс LLM-генерации с кэшем.
#   SCOPE: Данные и их проверка; не выполняет отображение (это M-MAPPER) и не ходит
#          в БД. LLM-вызовы только через переданный callable, в тестах - фикстуры.
#   DEPENDS: M-MAPPER (valid_inn/valid_snils/valid_ogrn для валидатора)
#   LINKS: M-MAPPER, V-M-CORPUS, docs/solution-design.md §3.1, §4.4
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   REQUIRED_KEYS - обязательные ключи компонент корпуса
#   load_components - чтение компонент корпуса из JSON (fixtures или кэш LLM)
#   build_corpora - компоненты -> словарь корпусов для Mapper
#   validate_corpus - формат/КС/дубли/длина; список нарушений
#   llm_components - генерация компонент через LLM-callable с кэшем на диске
# END_MODULE_MAP
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable



REQUIRED_KEYS = ["family", "name_m", "name_f", "patronymic_m", "patronymic_f",
                 "phone_code", "email_domain", "region", "city", "street", "org"]


def load_components(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = [k for k in REQUIRED_KEYS if not data.get(k)]
    if missing:
        raise ValueError(f"corpus components missing: {missing}")
    return data


def build_corpora(components: dict[str, list[str]]) -> dict[str, list[str]]:
    """Компоненты уже являются корпусами по типам; сборка ФИО комбинаторна
    в момент отображения (Mapper.fio берёт компоненты независимо), поэтому
    здесь только нормализация и дедупликация с сохранением порядка."""
    out: dict[str, list[str]] = {}
    for key, values in components.items():
        seen: dict[str, None] = {}
        for v in values:
            v = v.strip().lower().replace("ё", "е")
            if v and v not in seen:
                seen[v] = None
        out[key] = list(seen)
    return out






_RULES: dict[str, str] = {
    "phone_code": r"^\d{3}$",
    "email_domain": r"^[a-z0-9.-]+\.[a-z]{2,}$",
    "family": r"^[а-яе-]{2,}$",
    "name_m": r"^[а-яе-]{2,}$",
    "name_f": r"^[а-яе-]{2,}$",
    "patronymic_m": r"^[а-яе]{4,}$",
    "patronymic_f": r"^[а-яе]{4,}$",
}


# START_CONTRACT: validate_corpus
#   PURPOSE: Выход LLM не попадает в базу непроверенным (§4.4).
#   INPUTS: { corpora: dict - корпуса; max_len: dict|None - предел длины на ключ
#             (из длин колонок-потребителей) }
#   OUTPUTS: { list[str] - нарушения; пусто = валидно }
#   SIDE_EFFECTS: none
# END_CONTRACT: validate_corpus
def validate_corpus(corpora: dict[str, list[str]], max_len: dict[str, int] | None = None) -> list[str]:
    problems: list[str] = []
    for key, values in corpora.items():
        if len(values) != len(set(values)):
            problems.append(f"{key}: duplicates")
        if len(values) < 2:
            problems.append(f"{key}: fewer than 2 values (probing needs >=2)")
        rule = _RULES.get(key)
        if rule:
            bad = [v for v in values if not re.match(rule, v)]
            if bad:
                problems.append(f"{key}: format violations {bad[:3]}")
        if max_len and key in max_len:
            long = [v for v in values if len(v) > max_len[key]]
            if long:
                problems.append(f"{key}: exceeds column length {max_len[key]}: {long[:3]}")
    return problems







def llm_components(cache_path: Path, generate: Callable[[str], list[str]] | None = None) -> dict[str, list[str]]:
    """Компоненты от LLM с кэшем: файл есть - LLM не вызывается (воспроизводимость).
    generate(kind) -> список значений; None без кэша = ошибка (нет сети в тестах)."""
    if cache_path.exists():
        return load_components(cache_path)
    if generate is None:
        raise FileNotFoundError(f"no corpus cache at {cache_path} and no LLM provided")
    data = {k: generate(k) for k in REQUIRED_KEYS}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return data




# START_MODULE_CONTRACT
#   PURPOSE: Семантическая классификация колонок двумя независимыми источниками
#            сигнала: правила+Presidio по образцам значений, LLM по метаданным.
#            Расхождение или общая слепота -> unresolved (fail-closed).
#   SCOPE: Не назначает стратегии (это M-POLICY). LLM - через callable с кэшем
#          записанных ответов; в тестах сеть не нужна.
#   DEPENDS: M-PROFILER (Snapshot)
#   LINKS: M-POLICY, V-M-CLASSIFIER, docs/solution-design.md §4.3
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SemType - перечень семантических типов
#   PII_TYPES - множество типов, считающихся персональными данными
#   ClassifiedColumn - результат классификации колонки
#   rules_detect - правиловый детектор по значениям (КС: ИНН/СНИЛС/ОГРН; контекст: паспорт/КПП)
#   llm_classify - классификация по метаданным через callable с кэшем
#   classify - сведение двух голосов -> ClassifiedColumn(sem_type, confidence, unresolved)
# END_MODULE_MAP
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable

from sanitizer.mapper import valid_inn, valid_ogrn, valid_snils
from sanitizer.profiler import ColumnInfo




class SemType(StrEnum):
    FAMILY = "family"
    NAME = "name"
    PATRONYMIC = "patronymic"
    FIO_FULL = "fio_full"
    PHONE = "phone"
    EMAIL = "email"
    INN = "inn"
    SNILS = "snils"
    OGRN = "ogrn"
    PASSPORT = "passport"
    KPP = "kpp"
    ADDRESS = "address"
    CITY = "city"
    REGION = "region"
    ORG_NAME = "org_name"
    BIRTH_DATE = "birth_date"
    SALARY = "salary"
    FREE_TEXT = "free_text"
    CATEGORY = "category"
    PERSON_ID = "person_id"   # табельный номер и подобные внутренние идентификаторы людей
    TECHNICAL = "technical"


PII_TYPES = {SemType.FAMILY, SemType.NAME, SemType.PATRONYMIC, SemType.FIO_FULL,
             SemType.PHONE, SemType.EMAIL, SemType.INN, SemType.SNILS, SemType.OGRN,
             SemType.PASSPORT, SemType.ADDRESS, SemType.BIRTH_DATE, SemType.SALARY,
             SemType.FREE_TEXT, SemType.PERSON_ID}


@dataclass
class ClassifiedColumn:
    column: str
    sem_type: SemType | None
    confidence: float
    unresolved: bool
    reason: str






_PHONE_RE = re.compile(r"^\+?[78][\d\-\s()]{9,16}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zа-я]{2,}$", re.I)
_PASSPORT_RE = re.compile(r"^\d{4}\s?\d{6}$")
_KPP_RE = re.compile(r"^\d{9}$")
_NAMEISH_RE = re.compile(r"^[А-ЯЁ][а-яё\-]{2,}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

_CTX = {  # контекстные якоря для типов без контрольной суммы (§4.3)
    SemType.PASSPORT: ("passport", "паспорт", "серия", "doc"),
    SemType.KPP: ("kpp", "кпп"),
    SemType.BIRTH_DATE: ("birth", "рожден"),
    SemType.SALARY: ("salary", "amount", "зарплат", "оклад"),
}


def _ratio(samples: list[str], pred: Callable[[str], bool]) -> float:
    vals = [s for s in samples if s]
    return sum(1 for s in vals if pred(s)) / len(vals) if vals else 0.0


# START_CONTRACT: rules_detect
#   PURPOSE: Правиловый голос по значениям: контрольные суммы точны без контекста,
#            паспорт/КПП требуют контекстного якоря в имени колонки.
#   INPUTS: { col: ColumnInfo }
#   OUTPUTS: { (SemType|None, float) - тип и уверенность }
#   SIDE_EFFECTS: none
# END_CONTRACT: rules_detect
def rules_detect(col: ColumnInfo) -> tuple[SemType | None, float]:
    s, name = col.samples, col.name.lower()
    checks: list[tuple[SemType, float]] = [
        (SemType.INN, _ratio(s, lambda v: valid_inn(re.sub(r"\D", "", v)))),
        (SemType.SNILS, _ratio(s, lambda v: valid_snils(re.sub(r"\D", "", v)))),
        (SemType.OGRN, _ratio(s, lambda v: valid_ogrn(re.sub(r"\D", "", v)))),
        (SemType.PHONE, _ratio(s, lambda v: bool(_PHONE_RE.match(v)))),
        (SemType.EMAIL, _ratio(s, lambda v: bool(_EMAIL_RE.match(v)))),
    ]
    best, ratio = max(checks, key=lambda x: x[1])
    if ratio >= 0.9:
        return best, ratio
    # контекстно-зависимые: формат + якорь в имени
    for st, pattern in ((SemType.PASSPORT, _PASSPORT_RE), (SemType.KPP, _KPP_RE)):
        if _ratio(s, lambda v: bool(pattern.match(v))) >= 0.9 and any(a in name for a in _CTX[st]):
            return st, 0.9
    if _ratio(s, lambda v: bool(_DATE_RE.match(v))) >= 0.9 and any(a in name for a in _CTX[SemType.BIRTH_DATE]):
        return SemType.BIRTH_DATE, 0.9
    if _ratio(s, lambda v: bool(_NAMEISH_RE.match(v))) >= 0.9 and col.cardinality > 20:
        if "last" in name or "фамили" in name:
            return SemType.FAMILY, 0.6
        if "middle" in name or "отчеств" in name or "patronymic" in name:
            return SemType.PATRONYMIC, 0.6
        return SemType.NAME, 0.6
    if col.addr_parse_ratio is not None:
        # Уверенность следует за долей разборов, а не назначается константой:
        # прежние 0.7 звучали одинаково и при addr_parse=0.95, и при addr_parse=0.0,
        # то есть голос был увереннее, чем есть основания.
        return SemType.ADDRESS, round(0.4 + 0.5 * col.addr_parse_ratio, 2)
    avg_words = sum(len(v.split()) for v in s) / len(s) if s else 0
    if col.data_type == "text" or avg_words > 5:
        return SemType.FREE_TEXT, 0.7
    return None, 0.0







def llm_classify(cols: list[ColumnInfo], cache_path: Path,
                 ask: Callable[[dict], dict] | None = None) -> dict[str, tuple[SemType | None, float]]:
    """LLM-голос по метаданным (имена, типы, статистика - БЕЗ образцов ПДн).
    Кэш записанных ответов обязателен для CI; формат {column: [sem_type|null, conf]}."""
    if cache_path.exists():
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    else:
        if ask is None:
            raise FileNotFoundError(f"no LLM cache at {cache_path} and no provider")
        meta = {c.qualified: {"type": c.data_type, "len": c.max_len, "card": c.cardinality,
                              "null_frac": round(c.null_frac, 3), "json_keys": c.json_keys}
                for c in cols}
        raw = ask(meta)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(raw, ensure_ascii=False, indent=1), encoding="utf-8")
    return {k: (SemType(v[0]) if v[0] else None, float(v[1])) for k, v in raw.items()}







# START_CONTRACT: classify
#   PURPOSE: Сведение голосов. Согласие -> тип; расхождение по существу или
#            общая слепота -> unresolved (принудительный человеческий разбор).
#   INPUTS: { cols: list[ColumnInfo], llm_votes: dict из llm_classify }
#   OUTPUTS: { list[ClassifiedColumn] }
#   SIDE_EFFECTS: none
# END_CONTRACT: classify
def classify(cols: list[ColumnInfo], llm_votes: dict[str, tuple[SemType | None, float]]) -> list[ClassifiedColumn]:
    out = []
    for col in cols:
        r_type, r_conf = rules_detect(col)
        l_type, l_conf = llm_votes.get(col.qualified, (None, 0.0))
        # Суррогатный ключ - признак служебной колонки ТОЛЬКО когда ни один голос
        # не увидел смысла. `is_pk` означает «нельзя ломать уникальность», а не
        # «это не персональные данные»: PRIMARY KEY (snils) - обычная практика,
        # и такая колонка обязана пройти обычное сведение голосов (разбор 4, находка 1).
        surrogate = ((col.is_pk or col.name.endswith("_id"))
                     and col.data_type in ("integer", "bigint", "smallint", "uuid"))
        if surrogate and r_type is None and l_type is None:
            out.append(ClassifiedColumn(col.qualified, SemType.TECHNICAL, 1.0, False, "pk/fk-surrogate"))
        elif r_type and l_type and r_type == l_type:
            out.append(ClassifiedColumn(col.qualified, r_type, max(r_conf, l_conf), False, "agree"))
        elif r_type and l_type:  # расхождение по существу -> всегда человеку (§4.3)
            out.append(ClassifiedColumn(col.qualified, None, 0.0, True,
                                        f"disagree rules={r_type} llm={l_type}"))
        elif r_type and r_conf >= 0.9:
            out.append(ClassifiedColumn(col.qualified, r_type, r_conf, False, "rules-strong"))
        elif l_type and l_conf >= 0.8:
            out.append(ClassifiedColumn(col.qualified, l_type, l_conf, False, "llm-only"))
        elif r_type or l_type:
            out.append(ClassifiedColumn(col.qualified, None, 0.0, True, "weak-single-voice"))
        else:
            out.append(ClassifiedColumn(col.qualified, None, 0.0, True, "both-blind"))
    return out




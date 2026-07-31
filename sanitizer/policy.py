# START_MODULE_CONTRACT
#   PURPOSE: Назначение стратегии и LLM-режима по осям чувствительность×кардинальность,
#            модель sanitization-plan.yaml, fail-closed валидация, дифф планов.
#   SCOPE: Решения и их проверка; не исполняет замены и не ходит в LLM.
#   DEPENDS: M-CLASSIFIER (SemType, PII_TYPES), M-PROFILER (Snapshot), M-FK-CLOSURE
#   LINKS: M-PLAN-GRAPH, M-EXECUTOR, V-M-POLICY, docs/solution-design.md §3.1, §5.3
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   PlanColumn - решение по одной колонке
#   Plan - модель плана, YAML-сериализация
#   schema_fingerprint - отпечаток схемы для детекции дрейфа
#   DIRECT_THRESHOLD - порог кардинальности для прямого LLM-режима
#   FAKE_MIN_CARD - минимальная кардинальность для стратегии fake
#   ADDR_PARSE_THRESHOLD - порог разбираемости адресных строк
#   assign - ClassifiedColumn + Snapshot + классы -> Plan
#   validate_plan - fail-closed правила; список ошибок
#   plan_diff - новые/изменённые колонки между версиями
# END_MODULE_MAP
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from sanitizer.classifier import PII_TYPES, ClassifiedColumn, SemType
from sanitizer.fk_closure import equivalence_classes
from sanitizer.profiler import Snapshot

DIRECT_THRESHOLD = 10_000   # параметры плана, не константы кода (§3.1)
FAKE_MIN_CARD = 1_000
ADDR_PARSE_THRESHOLD = 0.9




@dataclass
class PlanColumn:
    sem_type: str
    strategy: str            # direct|fake|generate|generalize|shuffle|keep|null|freetext|jsonb|unresolved
    llm_mode: str            # direct|corpus|none - КТО произвёл материал замены
    reason: str
    confirmed: bool = False  # обязателен для null/generalize; проставляется ТОЛЬКО на гейте
    confirmed_by: str = ""   # human|ci - кто подтвердил; пусто = не подтверждено
    json_fields: dict[str, str] = field(default_factory=dict)
    # truncate|fail - для freetext (§5.5). Значения widen нет: расширение колонки
    # пришлось бы применять ДО pg_restore, а sanitization.sql едет после него -
    # то есть политика была неисполнима по построению (разбор 5, находка 6).
    length_policy: str = "fail"


@dataclass
class Plan:
    version: int
    schema_fingerprint: str
    columns: dict[str, PlanColumn]
    classes: list[list[str]]
    soft_links_pending: list[list[str]]
    params: dict
    # Первичные ключи таблиц едут в плане: исполнение работает по плану, а не по
    # догадке «колонка называется id». Без этого конвейер собирался только там,
    # где ключ действительно назван id (разбор 5, находка 9).
    primary_keys: dict[str, list[str]] = field(default_factory=dict)

    def dump(self, path: Path):
        data = {"version": self.version, "schema_fingerprint": self.schema_fingerprint,
                "params": self.params, "classes": self.classes,
                "primary_keys": self.primary_keys,
                "soft_links_pending": self.soft_links_pending,
                "columns": {k: asdict(v) for k, v in sorted(self.columns.items())}}
        path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")

    @staticmethod
    def load(path: Path) -> "Plan":
        d = yaml.safe_load(path.read_text(encoding="utf-8"))
        return Plan(d["version"], d["schema_fingerprint"],
                    {k: PlanColumn(**v) for k, v in d["columns"].items()},
                    d["classes"], d["soft_links_pending"], d["params"],
                    d.get("primary_keys", {}))

    def pk(self, table: str) -> str:
        """Единственная колонка первичного ключа таблицы либо ошибка с именем."""
        cols = self.primary_keys.get(table) or []
        if len(cols) != 1:
            raise ValueError(f"{table}: ожидался одноколоночный первичный ключ, в плане {cols}")
        return cols[0]


def schema_fingerprint(snap: Snapshot) -> str:
    # json_keys входят в отпечаток наравне с колонками: новый ключ внутри jsonb -
    # такой же дрейф схемы, как новая колонка, и без него он уезжает мимо гейта
    # (разбор 4, находка 3Б).
    payload = "|".join(f"{c.qualified}:{c.data_type}:{','.join(c.json_keys)}"
                       for c in sorted(snap.columns, key=lambda c: c.qualified))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# Семантические типы, для которых генерация структурно инъективна (перестановка
# Фейстеля или 40-битный суффикс). Только они допустимы на колонке-ключе.
_UNIQUE_SAFE = {SemType.INN, SemType.SNILS, SemType.OGRN, SemType.EMAIL,
                SemType.PERSON_ID}

# Типы разметки ключей jsonb, которые трансформер действительно умеет. Всё
# остальное он молча обнулял бы, а план выглядел бы корректным (разбор 5, находка 8).
_JSON_FIELD_TYPES = {"phone", "fio_full", "snils", "inn", "email", "passport",
                     "person_id", "keep"}






_STRATEGY: dict[SemType, tuple[str, str]] = {  # sem_type -> (strategy, llm_mode)
    SemType.FAMILY: ("fake", "corpus"), SemType.NAME: ("fake", "corpus"),
    SemType.PATRONYMIC: ("fake", "corpus"), SemType.FIO_FULL: ("fake", "corpus"),
    SemType.PHONE: ("fake", "corpus"), SemType.EMAIL: ("generate", "none"),
    SemType.INN: ("generate", "none"), SemType.SNILS: ("generate", "none"),
    SemType.OGRN: ("generate", "none"), SemType.PASSPORT: ("generate", "none"),
    SemType.KPP: ("keep", "none"),
    SemType.ADDRESS: ("fake", "corpus"),
    SemType.CITY: ("fake", "corpus"), SemType.REGION: ("fake", "corpus"),
    SemType.ORG_NAME: ("direct", "direct"),
    SemType.BIRTH_DATE: ("generalize", "none"), SemType.SALARY: ("shuffle", "none"),
    SemType.FREE_TEXT: ("freetext", "none"), SemType.CATEGORY: ("keep", "none"),
    SemType.PERSON_ID: ("generate", "none"), SemType.TECHNICAL: ("keep", "none"),
}


# START_CONTRACT: assign
#   PURPOSE: Стратегия по типу с поправками на кардинальность, адресную
#            разбираемость, jsonb и чувствительные категории.
#   INPUTS: { classified: list, snap: Snapshot, sensitive_categories: set[str] -
#             колонки-категории, требующие shuffle; json_map: dict - разметка jsonb }
#   OUTPUTS: { Plan }
#   SIDE_EFFECTS: none
# END_CONTRACT: assign
def assign(classified: list[ClassifiedColumn], snap: Snapshot,
           sensitive_categories: set[str] = frozenset(),
           json_map: dict[str, dict[str, str]] | None = None,
           llm_available: bool = False, params: dict | None = None) -> Plan:
    # Пороги - параметры плана (§3.1), а не константы кода: назначение и его
    # проверка обязаны читать одни и те же числа, иначе план и валидация
    # расходятся молча. Константы модуля остаются умолчанием.
    p = {"direct_threshold": DIRECT_THRESHOLD, "fake_min_cardinality": FAKE_MIN_CARD,
         "addr_parse_threshold": ADDR_PARSE_THRESHOLD, **(params or {}),
         "llm_available": llm_available}
    cols: dict[str, PlanColumn] = {}
    for cc in classified:
        info = snap.col(cc.column)
        if cc.unresolved:
            cols[cc.column] = PlanColumn("unknown", "unresolved", "none", cc.reason)
            continue
        st = cc.sem_type
        strategy, mode = _STRATEGY[st]
        reason = cc.reason
        if info.data_type == "jsonb":
            # Внутри jsonb действует то же правило, что для колонок: каждый ключ
            # должен быть размечен явно. Неразмеченный ключ - не «оставить как есть»,
            # а повод остановить план (разбор 4, находка 3А).
            fields = (json_map or {}).get(cc.column, {})
            unmapped = sorted(set(info.json_keys) - set(fields))
            if not fields:
                cols[cc.column] = PlanColumn(str(st), "unresolved", "none", "jsonb без разметки")
            elif unmapped:
                cols[cc.column] = PlanColumn(str(st), "unresolved", "none",
                                             f"jsonb: неразмеченные ключи {unmapped}",
                                             json_fields=fields)
            else:
                cols[cc.column] = PlanColumn(str(st), "jsonb", "none", "jsonb", json_fields=fields)
            continue
        if st == SemType.ADDRESS and (info.addr_parse_ratio or 0) < p["addr_parse_threshold"]:
            strategy, mode, reason = "freetext", "none", f"addr_parse={info.addr_parse_ratio}"  # §3.2 п.3
        if cc.column in sensitive_categories:
            strategy, mode, reason = "shuffle", "none", "sensitive-category"
        if strategy == "fake" and info.cardinality < p["fake_min_cardinality"] and st not in PII_TYPES:
            strategy, reason = "keep", f"low-card {info.cardinality}"          # §5.6
        # ПДн малой кардинальности: замена из корпуса восстановима частотой.
        # Раньше здесь стоял `pass` с комментарием «валидация потребует решения»,
        # а валидация проверяла только категориальные типы - ветка была мёртвой
        # и вводила в заблуждение (разбор 5, находка 11).
        if strategy == "fake" and info.cardinality < p["fake_min_cardinality"] and st in PII_TYPES:
            reason = f"{reason}; ПДн при кардинальности {info.cardinality}"
        if strategy == "direct" and (st in PII_TYPES or info.cardinality > p["direct_threshold"]):
            strategy, mode, reason = "fake", "corpus", "direct-forbidden"      # §3.1
        # Стратегия direct - это МАТЕРИАЛИЗОВАННАЯ карта 1:1 (инъективная по
        # построению). Кто её произвёл, говорит llm_mode: "direct" - модель,
        # "none" - детерминированный генератор из корпуса. Поставщика LLM в проекте
        # нет, поэтому режим понижается явно, а не подменяется молча (находка 11).
        if strategy == "direct" and not llm_available:
            mode, reason = "none", "карта 1:1 из корпуса (LLM не настроена)"
        if strategy == "generate" and st == SemType.EMAIL and not info.is_unique:
            strategy, mode = "fake", "corpus"
        # Колонка-ключ с персональными данными (PRIMARY KEY (snils), UNIQUE (email)):
        # замена обязана остаться инъективной. Иначе UNIQUE падает на restore, а
        # «починка» дублей означает сохранение части исходных значений (находка 1).
        if (info.is_pk or info.is_unique) and st in PII_TYPES:
            if st in _UNIQUE_SAFE:
                strategy, mode, reason = "generate", "none", f"{reason}; ключ-ПДн -> инъективная замена"
            else:
                strategy, mode, reason = "unresolved", "none", \
                    f"ключ-ПДн типа {st}: инъективной замены нет, нужно решение человека"
        cols[cc.column] = PlanColumn(str(st), strategy, mode, reason)

    classes = [sorted(c) for c in equivalence_classes(snap)]
    # Стратегия класса наследуется ТОЛЬКО между колонками одного семантического
    # типа. Прежняя версия переписывала strategy, не трогая sem_type: КПП, попав
    # в класс с колонкой-городом, получал fake и проваливался в ветку «название
    # организации» - 14 символов в varchar(9) и падение на restore. Замена должна
    # соответствовать типу колонки, иначе консистентность покупается порчей.
    for cls in classes:
        members = [c for c in cls if c in cols]
        types = {cols[c].sem_type for c in members if cols[c].sem_type != str(SemType.TECHNICAL)}
        if len(types) > 1:
            for c in members:
                cols[c] = PlanColumn(cols[c].sem_type, "unresolved", "none",
                                     f"класс связывает разные типы {sorted(types)}: нужно решение человека")
            continue
        strategies = {cols[c].strategy for c in members if cols[c].strategy != "keep"}
        if len(strategies) == 1:
            s = strategies.pop()
            for c in members:
                if cols[c].strategy == "keep" and cols[c].sem_type != str(SemType.TECHNICAL):
                    cols[c].strategy = s
    pks: dict[str, list[str]] = {}
    for c in snap.columns:
        if c.is_pk:
            pks.setdefault(c.table, []).append(c.name)
    return Plan(1, schema_fingerprint(snap), cols, classes, [], p, pks)







# START_CONTRACT: validate_plan
#   PURPOSE: Fail-closed валидация (§3.5, §5.3). Пустой список = план исполним.
#   INPUTS: { plan: Plan, snap: Snapshot - текущая схема }
#   OUTPUTS: { list[str] - ошибки }
#   SIDE_EFFECTS: none
# END_CONTRACT: validate_plan
def validate_plan(plan: Plan, snap: Snapshot) -> list[str]:
    errors: list[str] = []
    by_name = {c.qualified: c for c in snap.columns}
    pii_str = {str(t) for t in PII_TYPES}
    if plan.schema_fingerprint != schema_fingerprint(snap):
        missing = set(by_name) - set(plan.columns)
        errors.append(f"schema drift: fingerprint mismatch; columns not in plan: {sorted(missing)[:5]}")
    for name, pc in plan.columns.items():
        if pc.strategy == "unresolved":
            errors.append(f"{name}: unresolved ({pc.reason})")
        if pc.strategy == "direct" and pc.sem_type in pii_str:
            errors.append(f"{name}: PII type {pc.sem_type} in direct mode is forbidden")
        if pc.llm_mode == "direct" and not plan.params.get("llm_available", False):
            errors.append(f"{name}: llm_mode direct без настроенной LLM - механизма замены нет")
        if pc.strategy in ("null", "generalize") and not (pc.confirmed and pc.confirmed_by):
            errors.append(f"{name}: strategy {pc.strategy} requires human confirmation")
        if pc.length_policy not in ("truncate", "fail"):
            errors.append(f"{name}: length_policy {pc.length_policy!r} не реализована; "
                          f"допустимы truncate и fail")
        bad_json = sorted(set(pc.json_fields.values()) - _JSON_FIELD_TYPES)
        if bad_json:
            errors.append(f"{name}: разметка jsonb {bad_json} не поддерживается - "
                          f"такие ключи молча обнулялись бы")
        info = by_name.get(name)
        if info is not None and (info.is_pk or info.is_unique) and pc.sem_type in pii_str \
                and pc.strategy not in ("generate", "unresolved"):
            errors.append(f"{name}: ключ-ПДн ({pc.sem_type}) со стратегией {pc.strategy} - "
                          f"замена неинъективна, UNIQUE не удержится")
        if pc.strategy == "fake":
            # частотная атака (§5.6) актуальна для типов с ПУБЛИЧНО известным
            # распределением; для компонент ФИО риск принят явно (§6.2).
            # Запрет снимается подтверждением на гейте, а не молча: без LLM у
            # названий организаций иначе не остаётся ни одной допустимой стратегии
            # (direct невозможен, fake запрещён) - и инструмент вставал бы намертво.
            if pc.sem_type in ("category", "city", "region", "org_name", "kpp"):
                if info is None:
                    errors.append(f"{name}: column vanished from schema")
                elif info.cardinality < plan.params.get("fake_min_cardinality", FAKE_MIN_CARD) \
                        and not (pc.confirmed and pc.confirmed_by):
                    errors.append(f"{name}: fake at cardinality {info.cardinality} < min - "
                                  f"frequency attack (§5.6); нужно подтверждение на гейте")
    for cls in plan.classes:
        strategies = {plan.columns[c].strategy for c in cls if c in plan.columns}
        if len(strategies - {"keep"}) > 1:
            errors.append(f"class {cls}: conflicting strategies {sorted(strategies)}")
    return errors


_AUDIT_FIELDS = ("confirmed", "confirmed_by")


def _decision(pc: PlanColumn) -> dict:
    """Решение о замене без полей аудита: кто подтвердил - не часть решения."""
    return {k: v for k, v in asdict(pc).items() if k not in _AUDIT_FIELDS}


def plan_diff(old: Plan, new: Plan) -> dict[str, str]:
    """Колонка -> added|changed. Неизменённые не показываются (§3.5).
    Подтверждение проставляется на гейте, то есть ПОСЛЕ черновика, по которому
    считается дифф. Сравнивать его здесь значит показывать «changed» на каждом
    прогоне и приучать ревьюера пролистывать дифф не читая. Утрата подтверждения
    ловится не диффом, а валидацией (она блокирует план)."""
    out: dict[str, str] = {}
    for name, pc in new.columns.items():
        if name not in old.columns:
            out[name] = "added"
        elif _decision(pc) != _decision(old.columns[name]):
            out[name] = "changed"
    return out




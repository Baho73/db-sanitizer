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
    llm_mode: str            # direct|corpus|none
    reason: str
    confirmed: bool = False  # обязателен для null/generalize; проставляется на гейте
    json_fields: dict[str, str] = field(default_factory=dict)
    length_policy: str = "fail"  # truncate|widen|fail - для freetext (§5.5)


@dataclass
class Plan:
    version: int
    schema_fingerprint: str
    columns: dict[str, PlanColumn]
    classes: list[list[str]]
    soft_links_pending: list[list[str]]
    params: dict

    def dump(self, path: Path):
        data = {"version": self.version, "schema_fingerprint": self.schema_fingerprint,
                "params": self.params, "classes": self.classes,
                "soft_links_pending": self.soft_links_pending,
                "columns": {k: asdict(v) for k, v in sorted(self.columns.items())}}
        path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")

    @staticmethod
    def load(path: Path) -> "Plan":
        d = yaml.safe_load(path.read_text(encoding="utf-8"))
        return Plan(d["version"], d["schema_fingerprint"],
                    {k: PlanColumn(**v) for k, v in d["columns"].items()},
                    d["classes"], d["soft_links_pending"], d["params"])


def schema_fingerprint(snap: Snapshot) -> str:
    payload = "|".join(f"{c.qualified}:{c.data_type}" for c in sorted(snap.columns, key=lambda c: c.qualified))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]






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
           json_map: dict[str, dict[str, str]] | None = None) -> Plan:
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
            fields = (json_map or {}).get(cc.column, {})
            cols[cc.column] = PlanColumn(str(st), "jsonb" if fields else "unresolved",
                                         "none", "jsonb", json_fields=fields)
            continue
        if st == SemType.ADDRESS and (info.addr_parse_ratio or 0) < ADDR_PARSE_THRESHOLD:
            strategy, mode, reason = "freetext", "none", f"addr_parse={info.addr_parse_ratio}"  # §3.2 п.3
        if cc.column in sensitive_categories:
            strategy, mode, reason = "shuffle", "none", "sensitive-category"
        if strategy == "fake" and info.cardinality < FAKE_MIN_CARD and st not in PII_TYPES:
            strategy, reason = "keep", f"low-card {info.cardinality}"          # §5.6
        if strategy == "fake" and info.cardinality < FAKE_MIN_CARD and st in PII_TYPES:
            pass  # ПДн малой кардинальности: fake запрещён - валидация потребует решения
        if strategy == "direct" and (st in PII_TYPES or info.cardinality > DIRECT_THRESHOLD):
            strategy, mode, reason = "fake", "corpus", "direct-forbidden"      # §3.1
        if strategy == "generate" and st == SemType.EMAIL and not info.is_unique:
            strategy, mode = "fake", "corpus"
        cols[cc.column] = PlanColumn(str(st), strategy, mode, reason)

    classes = [sorted(c) for c in equivalence_classes(snap)]
    # стратегия класса: наследуется от неткехнической колонки класса
    for cls in classes:
        strategies = {cols[c].strategy for c in cls if c in cols and cols[c].strategy != "keep"}
        if len(strategies) == 1:
            s = strategies.pop()
            for c in cls:
                if c in cols and cols[c].strategy == "keep" and cols[c].sem_type != str(SemType.TECHNICAL):
                    cols[c].strategy = s
    return Plan(1, schema_fingerprint(snap), cols, classes, [],
                {"direct_threshold": DIRECT_THRESHOLD, "fake_min_cardinality": FAKE_MIN_CARD,
                 "addr_parse_threshold": ADDR_PARSE_THRESHOLD})







# START_CONTRACT: validate_plan
#   PURPOSE: Fail-closed валидация (§3.5, §5.3). Пустой список = план исполним.
#   INPUTS: { plan: Plan, snap: Snapshot - текущая схема }
#   OUTPUTS: { list[str] - ошибки }
#   SIDE_EFFECTS: none
# END_CONTRACT: validate_plan
def validate_plan(plan: Plan, snap: Snapshot) -> list[str]:
    errors: list[str] = []
    if plan.schema_fingerprint != schema_fingerprint(snap):
        snap_cols = {c.qualified for c in snap.columns}
        missing = snap_cols - set(plan.columns)
        errors.append(f"schema drift: fingerprint mismatch; columns not in plan: {sorted(missing)[:5]}")
    for name, pc in plan.columns.items():
        if pc.strategy == "unresolved":
            errors.append(f"{name}: unresolved ({pc.reason})")
        if pc.strategy == "direct" and pc.sem_type in {str(t) for t in PII_TYPES}:
            errors.append(f"{name}: PII type {pc.sem_type} in direct mode is forbidden")
        if pc.strategy in ("null", "generalize") and not pc.confirmed:
            errors.append(f"{name}: strategy {pc.strategy} requires human confirmation")
        if pc.strategy == "fake":
            # частотная атака (§5.6) актуальна для типов с ПУБЛИЧНО известным
            # распределением; для компонент ФИО риск принят явно (§6.2)
            if pc.sem_type in ("category", "city", "region", "org_name"):
                try:
                    card = snap.col(name).cardinality
                    if card < plan.params.get("fake_min_cardinality", FAKE_MIN_CARD):
                        errors.append(f"{name}: fake at cardinality {card} < min - frequency attack (§5.6)")
                except StopIteration:
                    errors.append(f"{name}: column vanished from schema")
    for cls in plan.classes:
        strategies = {plan.columns[c].strategy for c in cls if c in plan.columns}
        if len(strategies - {"keep"}) > 1:
            errors.append(f"class {cls}: conflicting strategies {sorted(strategies)}")
    return errors


def plan_diff(old: Plan, new: Plan) -> dict[str, str]:
    """Колонка -> added|changed. Неизменённые не показываются (§3.5)."""
    out: dict[str, str] = {}
    for name, pc in new.columns.items():
        if name not in old.columns:
            out[name] = "added"
        elif asdict(pc) != asdict(old.columns[name]):
            out[name] = "changed"
    return out




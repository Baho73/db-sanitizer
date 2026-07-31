# START_MODULE_CONTRACT
#   PURPOSE: Конвейер фазы планирования на LangGraph: профиль -> классификация ->
#            политика -> валидация -> человеческий гейт (interrupt) -> финализация.
#            Аппрув - узел графа с сохранением состояния (§4.5).
#   SCOPE: Оркестрация; вся логика в модулях-узлах. LLM только через кэши.
#   DEPENDS: M-PROFILER, M-CLASSIFIER, M-FK-CLOSURE, M-POLICY
#   LINKS: M-CLI, V-M-PLAN-GRAPH
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   PlanState - состояние графа планирования
#   apply_overrides - наложить разметку человека по белому списку полей
#   build_graph - собрать StateGraph с checkpointer
#   run_planning - выполнить до гейта; вернуть паузу или готовый план
#   resume_approved - продолжить после аппрува (Command(resume=...))
# END_MODULE_MAP
from __future__ import annotations

from pathlib import Path
from typing import TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from sanitizer.classifier import classify, llm_classify
from sanitizer.fk_closure import soft_links
from sanitizer.policy import Plan, assign, plan_diff, validate_plan
from sanitizer.profiler import Snapshot, profile




class PlanState(TypedDict, total=False):
    dsn: str
    schema: str
    llm_cache: str          # путь к кэшу LLM-классификации
    json_map: dict          # разметка jsonb-ключей (из кэша PolicyAgent)
    sensitive_categories: list[str]
    plan_path: str          # куда писать sanitization-plan.yaml
    auto_approve: bool      # CI-режим; пометка в отчёте
    overrides: dict         # решения человека по unresolved: колонка -> поля PlanColumn
    llm_available: bool     # настроен ли поставщик LLM; без него direct не назначается
    confirm: list[str]      # колонки, подтверждённые на гейте (null/generalize)
    confirmed_by: str       # human|ci - кто дал подтверждение
    snapshot_json: str
    errors: list[str]
    approved: bool
    diff: dict


_SNAP_CACHE: dict[str, Snapshot] = {}  # snapshot непереносим в JSON-состояние целиком

# Поля PlanColumn, которые человек вправе переопределить конфигом. `confirmed`
# и `confirmed_by` сюда НЕ входят: подтверждение выдаётся только на гейте, иначе
# неподписанный JSON подделывает человеческое решение (разбор 4, находка 4).
_OVERRIDABLE = {"sem_type", "strategy", "llm_mode", "reason", "json_fields", "length_policy"}







# START_CONTRACT: apply_overrides
#   PURPOSE: Наложить разметочные решения человека на план. Белый список полей -
#            единственная защита от подделки подтверждения неподписанным JSON.
#   INPUTS: { plan: Plan, overrides: dict колонка -> поля PlanColumn }
#   OUTPUTS: { none - план меняется на месте }
#   SIDE_EFFECTS: ValueError на неизвестной колонке или запрещённом поле (fail-closed)
# END_CONTRACT: apply_overrides
def apply_overrides(plan: Plan, overrides: dict) -> None:
    for col, fields in overrides.items():
        if col not in plan.columns:
            raise ValueError(f"override для неизвестной колонки {col}")
        for k, v in fields.items():
            if k not in _OVERRIDABLE:
                raise ValueError(f"override {col}.{k} запрещён; разрешено: {sorted(_OVERRIDABLE)}")
            setattr(plan.columns[col], k, v)


def _node_profile(state: PlanState) -> dict:
    snap = profile(state["dsn"], state.get("schema", "hr"))
    _SNAP_CACHE[state["dsn"]] = snap
    return {"snapshot_json": snap.to_json()}


def _node_classify_and_assign(state: PlanState) -> dict:
    snap = _SNAP_CACHE[state["dsn"]]
    votes = llm_classify(snap.columns, Path(state["llm_cache"]))
    classified = classify(snap.columns, votes)
    plan = assign(classified, snap,
                  sensitive_categories=set(state.get("sensitive_categories", [])),
                  json_map=state.get("json_map", {}),
                  llm_available=bool(state.get("llm_available")))
    # решения человека применяются ДО диффа и гейта: ревьюер видит итог,
    # а повторный прогон при неизменной схеме даёт пустой дифф
    apply_overrides(plan, state.get("overrides") or {})
    plan.soft_links_pending = [[a, b] for a, b, _ in soft_links(snap)]
    old_path = Path(state["plan_path"])
    diff = plan_diff(Plan.load(old_path), plan) if old_path.exists() else {}
    plan.dump(old_path.with_suffix(".draft.yaml"))
    return {"diff": diff, "errors": validate_plan(plan, snap)}


def _node_gate(state: PlanState) -> dict:
    """Человеческий гейт. interrupt() останавливает граф с сохранением состояния;
    продолжение - Command(resume={"approve": bool, "confirm": [колонки]})."""
    if state.get("auto_approve"):
        # CI-режим: подтверждения берутся из конфига и помечаются машинными -
        # в самом плане видно, что человека на гейте не было
        return {"approved": True, "confirm": list(state.get("confirm") or []), "confirmed_by": "ci"}
    answer = interrupt({
        "plan_draft": str(Path(state["plan_path"]).with_suffix(".draft.yaml")),
        "diff": state.get("diff", {}),
        "validation_errors": state.get("errors", []),
    })
    return {"approved": bool(answer.get("approve")),
            "confirm": list(answer.get("confirm") or []), "confirmed_by": "human"}


def _node_finalize(state: PlanState) -> dict:
    draft = Path(state["plan_path"]).with_suffix(".draft.yaml")
    plan = Plan.load(draft)
    snap = _SNAP_CACHE[state["dsn"]]
    for col in state.get("confirm") or []:
        if col not in plan.columns:
            return {"errors": [f"подтверждение для неизвестной колонки {col}"], "approved": False}
        plan.columns[col].confirmed = True
        plan.columns[col].confirmed_by = state.get("confirmed_by") or "human"
    errors = validate_plan(plan, snap)
    if errors:
        return {"errors": errors, "approved": False}
    plan.dump(Path(state["plan_path"]))
    return {"errors": []}







def build_graph():
    g = StateGraph(PlanState)
    g.add_node("profile", _node_profile)
    g.add_node("classify_assign", _node_classify_and_assign)
    g.add_node("gate", _node_gate)
    g.add_node("finalize", _node_finalize)
    g.add_edge(START, "profile")
    g.add_edge("profile", "classify_assign")
    g.add_edge("classify_assign", "gate")
    g.add_conditional_edges("gate", lambda s: "finalize" if s.get("approved") else END)
    g.add_edge("finalize", END)
    return g.compile(checkpointer=MemorySaver())


def run_planning(graph, state: PlanState, thread_id: str = "plan") -> dict:
    cfg = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(state, cfg)


def resume_approved(graph, thread_id: str = "plan", confirm: list[str] = ()) -> dict:
    cfg = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(Command(resume={"approve": True, "confirm": list(confirm)}), cfg)




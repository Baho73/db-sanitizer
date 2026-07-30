# GRACE 4 Project Engineering Protocol

## Keywords
sanitization, anonymization, pseudonymization, PostgreSQL, Greenmask, LangGraph, Presidio, LLM, PII, 152-FZ, RKN-140, dump, deterministic-masking

## Annotation
db-sanitizer — инструмент санитизации (обезличивания) PostgreSQL-баз для передачи копий за пределы прод-контура. LLM-агенты (LangGraph) на метаданных производят план санитизации и материал замен; исполнение — два детерминированных прохода: Greenmask + Cmd-трансформер (структурные колонки), обвязка над directory-дампом (свободный текст, схема sanitization). Консистентность — HMAC/SHA3 по ключу идентичности, производная соль по получателю и поколению. Нормативный проектный документ: `docs/solution-design.md` (редакция 4); ТЗ: `TZ.md`.

## GRACE 4 Source of Truth

This project uses the GRACE 4 `.grace` artifact model.

- Product and technical context: `.grace/context/*.xml`
- Current graph projection source: `.grace/graph/index.xml` plus routed graph documents such as `.grace/graph/main.xml`
- Current verification projection source: `.grace/verification/index.xml` plus routed verification documents such as `.grace/verification/main.xml`
- Active work: `.grace/changes/active/C-*/spec.xml` and `.grace/changes/active/C-*/plan.xml`
- Completed or terminal work: `.grace/changes/archive/C-*/*`

Legacy `docs/*.xml` files are not GRACE 4 state. If legacy GRACE 3 docs appear, use `grace-migrate`; do not silently validate, convert, or delete them.

## Workflow Rules

1. Do not implement source behavior before an approved active `GraceChangeSpec` and `GraceChangePlan` exist, unless the user explicitly requests a small direct fix.
2. Treat `spec.xml` as normative. Treat `design-context.xml` as explanatory memory only.
3. Before execution, check `BaselineAssertions`, `TargetAssertions`, `DurableScope`, and `ObservedWriteScope` in the plan.
4. Update durable `.grace` graph and verification state only as part of the approved change lifecycle.
5. Never store transient run state by mutating approved XML statuses. Runtime states are derived from current files, assertions, and scopes.

## Semantic Anchor Rules

- GRACE semantic anchors are XML tags, never attributes: use `<M-EXAMPLE />`, not `<Module ref="M-EXAMPLE" />`.
- Module IDs use `M-*`; data-flow IDs use `DF-*`; graph document wrappers use `GD-*`; verification entries use deterministic `V-M-*`; verification document wrappers use `VD-*`; change bundles use `C-*`.
- Code-level semantic markup remains grep-stable: `START_MODULE_CONTRACT`, `START_MODULE_MAP`, `START_CONTRACT:`, `START_BLOCK_`, and `START_CHANGE_SUMMARY`.

## Grep-First Navigation

1. Locate module ownership through `.grace/graph/index.xml`, then open the routed graph document.
2. Locate verification through `.grace/verification/index.xml`, then open the routed verification document.
3. Locate active work through `.grace/changes/active/C-*`.
4. Use file-local `LINKS:` fields and `START_BLOCK_` anchors to narrow code reads before loading whole files.

## CLI Checks

- `grace lint --path .` validates `.grace` grammar, projections, assertions, lifecycle locations, and scope overlaps.
- `grace status --path .` summarizes durable and operational GRACE 4 health.
- `grace module`, `grace verification`, and `grace file` navigate graph, verification, and file-local anchors.

## File-Local Markup Reference

```python
# START_MODULE_CONTRACT
#   PURPOSE: [What this module does]
#   SCOPE: [Bounded responsibility]
#   DEPENDS: [M-* dependencies or none]
#   LINKS: [Related M-* and V-M-* anchors]
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   exportedSymbol - one-line responsibility
# END_MODULE_MAP
#
# START_CONTRACT: functionName
#   PURPOSE: [What it does]
#   INPUTS: { paramName: Type - description }
#   OUTPUTS: { ReturnType - description }
#   SIDE_EFFECTS: [External state changes or none]
# END_CONTRACT: functionName
#
# START_BLOCK_EXAMPLE
# ... implementation slice ...
# END_BLOCK_EXAMPLE
```

## Project-Specific Rules

- Ponytail: `lite` по умолчанию; поднимать до `full` только на стадии кодогенерации (grace-execute).
- Перед проектированием контрактов рисковых модулей — сверяться с `docs/solution-design.md`; документ нормативен для архитектурных решений (приложения А и Б фиксируют принятые решения и разрешённые противоречия).
- Реальные ПДн не появляются ни в тестах, ни в фикстурах, ни в git — только синтетика (Faker/LLM).

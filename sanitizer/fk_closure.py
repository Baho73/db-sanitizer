# START_MODULE_CONTRACT
#   PURPOSE: Классы эквивалентности колонок: объявленные FK (включая композитные,
#            поколоночно) + мягкие связи по вложенности доменов значений.
#            Стратегия назначается классу; конфликт внутри класса - ошибка.
#   SCOPE: Только группировка; сами стратегии назначает M-POLICY.
#   DEPENDS: M-PROFILER (Snapshot)
#   LINKS: M-POLICY, V-M-FK-CLOSURE, docs/solution-design.md §5.1
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   equivalence_classes - разбиение колонок на классы по FK-графу
#   soft_links - кандидаты мягких связей (домен A ⊆ домен B), на подтверждение
# END_MODULE_MAP
from __future__ import annotations

from sanitizer.profiler import Snapshot




class _DSU:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str):
        self.p[self.find(a)] = self.find(b)





# START_CONTRACT: equivalence_classes
#   PURPOSE: Колонки, связанные FK (поколоночно, композитные по позициям),
#            попадают в один класс - им положена одна стратегия и один корпус.
#   INPUTS: { snap: Snapshot, extra_links: list[tuple[str, str]] - подтверждённые
#             мягкие связи (qualified -> qualified) }
#   OUTPUTS: { list[set[str]] - классы размером >= 2 }
#   SIDE_EFFECTS: none
# END_CONTRACT: equivalence_classes
def equivalence_classes(snap: Snapshot, extra_links: list[tuple[str, str]] = ()) -> list[set[str]]:
    dsu = _DSU()
    for fk in snap.fks:
        for src_c, dst_c in zip(fk.src_cols, fk.dst_cols):
            dsu.union(f"{fk.src_table}.{src_c}", f"{fk.dst_table}.{dst_c}")
    for a, b in extra_links:
        dsu.union(a, b)
    groups: dict[str, set[str]] = {}
    for col in list(dsu.p):
        groups.setdefault(dsu.find(col), set()).add(col)
    return [g for g in groups.values() if len(g) >= 2]


# START_CONTRACT: soft_links
#   PURPOSE: Кандидаты связей без констрейнта: домен значений A вложен в домен B.
#            Выход - «подозрение, подтвердить человеком», не автосвязь (§6.2).
#   INPUTS: { snap: Snapshot, threshold: float - минимальная доля вложенности }
#   OUTPUTS: { list[(src, dst, overlap)] }
#   SIDE_EFFECTS: none
# END_CONTRACT: soft_links
def soft_links(snap: Snapshot, threshold: float = 0.85) -> list[tuple[str, str, float]]:
    fk_pairs = {(f"{fk.src_table}.{c1}", f"{fk.dst_table}.{c2}")
                for fk in snap.fks for c1, c2 in zip(fk.src_cols, fk.dst_cols)}
    cands = [c for c in snap.columns
             if not c.is_pk and c.data_type in ("character varying", "text")
             and 1 < c.cardinality and c.samples]
    out = []
    for a in cands:
        sa = set(a.samples)
        for b in cands:
            if a.qualified >= b.qualified or (a.qualified, b.qualified) in fk_pairs:
                continue
            sb = set(b.samples)
            inter = len(sa & sb) / min(len(sa), len(sb))
            if inter >= threshold:
                out.append((a.qualified, b.qualified, round(inter, 3)))
    return sorted(out, key=lambda x: -x[2])


# END_BLOCK — конец модуля

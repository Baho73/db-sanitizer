# START_MODULE_CONTRACT
#   PURPOSE: Верификация «до/после» на staging (§5.4, §7): канарейки, fake(x)!=x,
#            объём, ограничения, энтропия с исключениями по стратегиям,
#            сквозная консистентность, чек-суммы для воспроизводимости.
#   SCOPE: Читает обе БД; сам проверяется канареечным набором. Красный критерий -
#          ненулевой код выхода и блокировка публикации через run_log.
#   DEPENDS: M-POLICY (план), M-RUNLOG
#   LINKS: V-M-VERIFIER, docs/solution-design.md §5.4, §7
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   verify - все проверки
#   VerifyReport - отчёт со статусами
#   Check - одна проверка
#   entropy - энтропия Шеннона по счётчикам
#   column_checksums - поколоночные md5 для сравнения прогонов (e2e)
#   render_markdown - отчёт-таблица
# END_MODULE_MAP
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from sanitizer.policy import Plan




@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def add(self, name: str, passed: bool, detail: str = ""):
        self.checks.append(Check(name, passed, detail))


def render_markdown(r: VerifyReport) -> str:
    lines = ["| Проверка | Статус | Детали |", "|---|---|---|"]
    lines += [f"| {c.name} | {'✅' if c.passed else '❌'} | {c.detail} |" for c in r.checks]
    return "\n".join(lines)


def entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    return -sum(c / total * math.log2(c / total) for c in counts if c)






_TEXTLIKE = ("character varying", "text", "jsonb")


# START_CONTRACT: verify
#   PURPOSE: Полный набор проверок §7 против источника и восстановленной копии.
#   INPUTS: { src_dsn, dst_dsn, plan, canary_manifest: Path, entropy_drop_max: float }
#   OUTPUTS: { VerifyReport }
#   SIDE_EFFECTS: только чтение обеих БД
# END_CONTRACT: verify
def verify(src_dsn: str, dst_dsn: str, plan: Plan, canary_manifest: Path,
           entropy_drop_max: float = 0.10) -> VerifyReport:
    import psycopg

    manifest = json.loads(canary_manifest.read_text(encoding="utf-8"))
    canaries: dict[str, str] = manifest["values"]
    r = VerifyReport()

    with psycopg.connect(src_dsn) as src, psycopg.connect(dst_dsn) as dst:
        s, d = src.cursor(), dst.cursor()

        tables = _tables(s)
        text_cols = _text_columns(s, tables)

        # 1. Объём: count(*) совпадает
        bad = []
        for t in tables:
            s.execute(f"SELECT count(*) FROM {t}")
            d.execute(f"SELECT count(*) FROM {t}")
            if s.fetchone()[0] != d.fetchone()[0]:
                bad.append(t)
        r.add("Объём: count(*) по таблицам", not bad, f"расхождения: {bad}" if bad else f"{len(tables)} таблиц")

        # 2. Канарейки: K из K в источнике, 0 из K в копии (включая хвост адреса)
        found_src = {k for k, v in canaries.items() if _found_anywhere(s, text_cols, v)}
        found_dst = {k for k, v in canaries.items() if _found_anywhere(d, text_cols, v)}
        r.add("Канарейки в источнике", found_src == set(canaries),
              f"{len(found_src)}/{len(canaries)}")
        r.add("Канарейки в копии отсутствуют", not found_dst,
              f"утекли: {sorted(found_dst)}" if found_dst else "0 из K")

        # 3. fake(x)!=x построчно для direct/fake/generate (§5.4)
        offenders = []
        for qualified, pc in plan.columns.items():
            if pc.strategy not in ("direct", "fake", "generate"):
                continue
            table, col = qualified.rsplit(".", 1)
            src_vals = _col_by_pk(s, table, col)
            dst_vals = _col_by_pk(d, table, col)
            same = [pk for pk, v in src_vals.items()
                    if v is not None and dst_vals.get(pk) == v]
            if same:
                offenders.append(f"{qualified}:{len(same)}")
        r.add("Построчно fake(x) != x", not offenders,
              "; ".join(offenders) if offenders else "все direct/fake/generate чисты")

        # 4. Ссылочная целостность: рестор прошёл с констрейнтами; сверяем их число
        s.execute(_FK_COUNT)
        d.execute(_FK_COUNT)
        src_fk, dst_fk = s.fetchone()[0], d.fetchone()[0]
        r.add("FK: все ограничения восстановлены", src_fk == dst_fk, f"{dst_fk}/{src_fk}")

        # 5. Энтропия с исключениями по стратегиям (§5.4)
        drops = []
        for qualified, pc in plan.columns.items():
            if pc.strategy not in ("fake", "generate", "direct", "shuffle", "keep"):
                continue  # generalize/null/freetext/jsonb - свои ожидания
            table, col = qualified.rsplit(".", 1)
            e_src = _col_entropy(s, table, col)
            e_dst = _col_entropy(d, table, col)
            if e_src > 1.0 and e_dst < e_src * (1 - entropy_drop_max):
                drops.append(f"{qualified}: {e_src:.2f}->{e_dst:.2f}")
        r.add("Разнообразие: просадка энтропии <= 10%", not drops,
              "; ".join(drops) if drops else "в пределах порога")

        # 6. Сквозная консистентность: канареечная личность во всех местах -> одна замена
        emp_id = manifest["employee_id"]
        d.execute("SELECT last_name FROM hr.employees WHERE id = %s", (emp_id,))
        fam = d.fetchone()[0]
        d.execute("SELECT comment_text FROM hr.ticket_comments WHERE ticket_id = %s "
                  "ORDER BY id DESC LIMIT 1", (manifest["ticket_id"],))
        comment = d.fetchone()[0]
        d.execute("SELECT body_text FROM hr.tickets WHERE id = %s", (manifest["ticket_id"],))
        body = d.fetchone()[0]
        fam_base = fam.rstrip("а")  # женская форма в склейке «Канарейкина В.П.»
        r.add("Сквозная консистентность (таблица+склейка+текст)",
              fam in body and fam_base in comment,
              f"employees='{fam}', в тексте={'да' if fam in body else 'НЕТ'}, "
              f"в склейке={'да' if fam_base in comment else 'НЕТ'}")

        # 7. Мягкая связь: одинаковый исходный ИНН -> одинаковая замена в обеих таблицах
        d.execute("SELECT inn FROM hr.employees WHERE id = %s", (emp_id,))
        emp_inn = d.fetchone()[0]
        d.execute("SELECT inn FROM hr.contractors ORDER BY id DESC LIMIT 1")
        contractor_inn = d.fetchone()[0]
        r.add("Мягкая связь по ИНН консистентна", emp_inn == contractor_inn,
              f"{emp_inn} == {contractor_inn}")

    return r


def _tables(cur) -> list[str]:
    cur.execute("SELECT table_schema || '.' || table_name FROM information_schema.tables "
                "WHERE table_schema = 'hr' AND table_type = 'BASE TABLE' ORDER BY 1")
    return [r[0] for r in cur.fetchall()]


def _text_columns(cur, tables: list[str]) -> dict[str, list[str]]:
    cur.execute("SELECT table_schema || '.' || table_name, column_name "
                "FROM information_schema.columns WHERE table_schema = 'hr' "
                f"AND data_type IN {_TEXTLIKE}")
    out: dict[str, list[str]] = {}
    for t, c in cur.fetchall():
        out.setdefault(t, []).append(c)
    return out


def _found_anywhere(cur, text_cols: dict[str, list[str]], needle: str) -> bool:
    for table, cols in text_cols.items():
        conds = " OR ".join(f"{c}::text ILIKE %s" for c in cols)
        cur.execute(f"SELECT 1 FROM {table} WHERE {conds} LIMIT 1",
                    [f"%{needle}%"] * len(cols))
        if cur.fetchone():
            return True
    return False


def _col_by_pk(cur, table: str, col: str) -> dict:
    pk = "contract_id::text || '/' || item_no::text" if table == "hr.contract_items" else "id::text"
    cur.execute(f"SELECT {pk}, {col}::text FROM {table}")
    return dict(cur.fetchall())


def _col_entropy(cur, table: str, col: str) -> float:
    cur.execute(f"SELECT count(*) FROM {table} GROUP BY {col}")
    return entropy([r[0] for r in cur.fetchall()])


_FK_COUNT = ("SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
             "WHERE c.contype IN ('f','u','p') AND t.relnamespace::regnamespace::text = 'hr'")


def column_checksums(dsn: str, plan: Plan) -> dict[str, str]:
    """Поколоночные md5 для сравнения двух прогонов (§7 воспроизводимость).
    Свободнотекстовые колонки включаются только при перенесённом кэше."""
    import psycopg

    out: dict[str, str] = {}
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        for qualified, pc in plan.columns.items():
            if pc.strategy in ("keep", "unresolved"):
                continue
            table, col = qualified.rsplit(".", 1)
            pk = "contract_id, item_no" if table == "hr.contract_items" else "id"
            cur.execute(f"SELECT md5(string_agg({col}::text, '' ORDER BY {pk})) FROM {table}")
            out[qualified] = cur.fetchone()[0] or ""
    return out




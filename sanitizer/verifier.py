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
#   Check - одна проверка (может быть помечена пропущенной)
#   entropy - энтропия Шеннона по счётчикам
#   column_checksums - поколоночные md5 для сравнения прогонов (e2e)
#   render_markdown - отчёт-таблица
# END_MODULE_MAP
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from sanitizer.policy import Plan
from sanitizer.profiler import ident




@dataclass
class Check:
    name: str
    passed: bool
    detail: str
    skipped: bool = False


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        # Пропущенная проверка НЕ засчитывается пройденной: непроведённая проверка
        # ничего не доказывает, а публикация решается по этому флагу. Метка ⏭
        # остаётся, чтобы отличить «не проверяли» от «проверили и упало».
        return all(c.passed for c in self.checks)

    def add(self, name: str, passed: bool, detail: str = "", skipped: bool = False):
        self.checks.append(Check(name, passed, detail, skipped))


def render_markdown(r: VerifyReport) -> str:
    lines = ["| Проверка | Статус | Детали |", "|---|---|---|"]
    # пропущенная проверка помечается отдельно: зелёная галочка на непроведённой
    # проверке - это ровно то, чем верификатор обманывал сам себя
    lines += [f"| {c.name} | {'⏭' if c.skipped else '✅' if c.passed else '❌'} | {c.detail} |"
              for c in r.checks]
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
           entropy_drop_max: float = 0.10, schema: str | None = None,
           corpus_sizes: dict[str, int] | None = None) -> VerifyReport:
    import psycopg
    from psycopg import sql

    manifest = json.loads(canary_manifest.read_text(encoding="utf-8"))
    canaries: dict[str, str] = manifest["values"]
    r = VerifyReport()
    # схема берётся из плана, а не зашита: вся правая половина V-модели иначе
    # существует только для демонстрационной hr (разбор 4, находка 15).
    # План на несколько схем не проверяется молча по первой из них.
    schemas = sorted({q.split(".", 1)[0] for q in plan.columns})
    if schema is None:
        if len(schemas) != 1:
            raise ValueError(f"план охватывает схемы {schemas}; укажите проверяемую явно")
        schema = schemas[0]

    with psycopg.connect(src_dsn) as src, psycopg.connect(dst_dsn) as dst:
        s, d = src.cursor(), dst.cursor()

        tables = _tables(s, schema)
        text_cols = _text_columns(s, schema)
        pk_of = _primary_keys(s, schema)

        # 1. Объём: count(*) совпадает
        bad = []
        for t in tables:
            q = sql.SQL("SELECT count(*) FROM {}").format(ident(t))
            s.execute(q)
            d.execute(q)
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
            pk_expr = _pk_expr(pk_of, table)
            src_vals = _col_by_pk(s, table, col, pk_expr)
            dst_vals = _col_by_pk(d, table, col, pk_expr)
            same = [pk for pk, v in src_vals.items()
                    if v is not None and dst_vals.get(pk) == v]
            if same:
                offenders.append(f"{qualified}:{len(same)}")
        r.add("Построчно fake(x) != x", not offenders,
              "; ".join(offenders) if offenders else "все direct/fake/generate чисты")

        # 3b. Идентификаторы источника не встречаются в копии НИГДЕ - ни в
        # структурных колонках, ни в свободном тексте. Проверка не зависит от
        # канареек и от того, какие форматы умеет распознавать проход 2: она
        # сравнивает КОНТРОЛЬНЫЕ СУММЫ. Именно её отсутствие позволило 783 СНИЛС
        # уехать в копию при девяти зелёных проверках (разбор 5, находка 1).
        leaked = _identifier_leak(s, d, plan, text_cols)
        r.add("Идентификаторы источника отсутствуют в копии (по контрольным суммам)",
              not leaked, "; ".join(leaked[:5]) if leaked else "ИНН/СНИЛС/ОГРН источника не найдены")

        # 3c. Деградации прохода 2 - это фрагменты, оставленные без изменений.
        # Их допустимое число объявляется планом и проходит гейт, а не молчит.
        _degradation_check(r, d, plan)

        # 4. Ссылочная целостность: рестор прошёл с констрейнтами; сверяем их число
        s.execute(_FK_COUNT, (schema,))
        d.execute(_FK_COUNT, (schema,))
        src_fk, dst_fk = s.fetchone()[0], d.fetchone()[0]
        r.add("FK: все ограничения восстановлены", src_fk == dst_fk, f"{dst_fk}/{src_fk}")

        # 5. Энтропия с исключениями по стратегиям (§5.4). Порог применяется к
        # ДОСТИЖИМОМУ разнообразию: замена из корпуса размера m по хэшу даёт в
        # среднем m·(1−e^(−n/m)) различных значений, и при n, сравнимом с m,
        # просадка неизбежна физически. Требовать здесь исходную энтропию значит
        # обещать разнообразие, которого корпус не содержит (разбор 5).
        drops, capped = [], []
        for qualified, pc in plan.columns.items():
            if pc.strategy not in ("fake", "generate", "direct", "shuffle", "keep"):
                continue  # generalize/null/freetext/jsonb - свои ожидания
            table, col = qualified.rsplit(".", 1)
            e_src = _col_entropy(s, table, col)
            e_dst = _col_entropy(d, table, col)
            if e_src <= 1.0:
                continue
            limit = e_src
            ceiling = _corpus_ceiling(pc, s, table, col, corpus_sizes)
            if ceiling is not None and ceiling < e_src:
                limit = ceiling
                capped.append(f"{qualified} (потолок корпуса {ceiling:.2f})")
            if e_dst < limit * (1 - entropy_drop_max):
                drops.append(f"{qualified}: {e_src:.2f}->{e_dst:.2f} при пределе {limit:.2f}")
        detail = "; ".join(drops) if drops else "в пределах порога"
        if capped and not drops:
            detail += f"; ограничено корпусом: {', '.join(capped)}"
        r.add("Разнообразие: просадка энтропии <= 10% от достижимого", not drops, detail)

        # 6-7. Пробы сквозной консистентности задаются манифестом канареек, а не
        # зашиты в код: на чужой базе таблиц employees и tickets может не быть.
        _consistency_checks(r, d, manifest)

    return r


_DIGIT_RUN_RE = re.compile(r"\d[\d\s-]{8,17}\d")


def _corpus_ceiling(pc, s, table: str, col: str,
                    corpus_sizes: dict[str, int] | None) -> float | None:
    from psycopg import sql

    """Достижимая энтропия колонки со стратегией fake: сколько различных значений
    в принципе может дать корпус при отображении n исходников хэшем в m ячеек."""
    if pc.strategy != "fake" or not corpus_sizes:
        return None
    from sanitizer.corpus import SEM_TO_CORPUS

    keys = SEM_TO_CORPUS.get(pc.sem_type, ())
    sizes = [corpus_sizes[k] for k in keys if k in corpus_sizes]
    if not sizes:
        return None
    m = min(sizes)
    s.execute(sql.SQL("SELECT count(DISTINCT {c}) FROM {t}").format(c=ident(col), t=ident(table)))
    n = s.fetchone()[0] or 0
    if not n or not m:
        return None
    distinct = m * (1 - math.exp(-n / m))
    return math.log2(max(distinct, 1))


# START_CONTRACT: _identifier_leak
#   PURPOSE: Найти в копии значения ИНН/СНИЛС/ОГРН источника, независимо от их
#            написания. Опознание идёт по контрольной сумме, поэтому проверка не
#            наследует слепоту того слоя, который она проверяет.
#   INPUTS: { s: курсор источника, d: курсор копии, plan, text_cols }
#   OUTPUTS: { list[str] - «таблица.колонка: сколько значений» }
#   SIDE_EFFECTS: чтение обеих БД
# END_CONTRACT: _identifier_leak
def _identifier_leak(s, d, plan: Plan, text_cols: dict[str, list[str]]) -> list[str]:
    from psycopg import sql

    from sanitizer.mapper import normalize_digits, valid_inn, valid_ogrn, valid_snils

    wanted: set[str] = set()
    for qualified, pc in plan.columns.items():
        if pc.sem_type not in ("inn", "snils", "ogrn"):
            continue
        table, col = qualified.rsplit(".", 1)
        s.execute(sql.SQL("SELECT DISTINCT {c}::text FROM {t} WHERE {c} IS NOT NULL")
                  .format(c=ident(col), t=ident(table)))
        wanted |= {normalize_digits(r[0]) for r in s.fetchall()}
    wanted = {w for w in wanted if valid_inn(w) or valid_snils(w) or valid_ogrn(w)}
    if not wanted:
        return []

    found: list[str] = []
    for table, cols in sorted(text_cols.items()):
        for col in cols:
            d.execute(sql.SQL("SELECT {c}::text FROM {t} WHERE {c} IS NOT NULL")
                      .format(c=ident(col), t=ident(table)))
            hits = 0
            for (value,) in d.fetchall():
                for run in _DIGIT_RUN_RE.findall(value):
                    if normalize_digits(run) in wanted:
                        hits += 1
            if hits:
                found.append(f"{table}.{col}: {hits}")
    return found


def _degradation_check(r: VerifyReport, d, plan: Plan):
    """Проход 2 фиксирует деградации в sanitization.summary. Порог - решение
    человека, объявленное в плане; молчаливое умолчание здесь означало бы, что
    неразобранный фрагмент уезжает в копию без единого следа."""
    allowed = plan.params.get("max_degraded")
    try:
        d.execute("SELECT coalesce(sum(degraded), 0) FROM sanitization.summary")
        total = d.fetchone()[0]
    except Exception:
        r.add("Деградации прохода 2 в пределах объявленного порога", False,
              "схемы sanitization нет в копии - проход 2 не отчитался", skipped=True)
        return
    if allowed is None:
        r.add("Деградации прохода 2 в пределах объявленного порога", False,
              f"деградаций {total}, порог max_degraded в плане не объявлен")
        return
    r.add("Деградации прохода 2 в пределах объявленного порога", total <= allowed,
          f"{total} <= {allowed}" if total <= allowed else f"{total} > {allowed}")


# START_CONTRACT: _consistency_checks
#   PURPOSE: Пробы «одна личность - одна замена везде» и «мягкая связь по ИНН».
#            Места проб описывает манифест канареек (секция probes); без неё
#            проверки помечаются пропущенными, а не зелёными.
#   INPUTS: { r: VerifyReport, cur: курсор копии, manifest: dict }
#   OUTPUTS: { none - отчёт пополняется }
#   SIDE_EFFECTS: чтение копии
# END_CONTRACT: _consistency_checks
def _probe_sql(probe: dict, order: bool = False):
    """Проба из манифеста -> запрос с квотированными идентификаторами.
    Манифест - файл рядом с дампом, его содержимое в SQL не подставляется сырым."""
    from psycopg import sql

    q = sql.SQL("SELECT {c} FROM {t} WHERE {k} = %s").format(
        c=ident(probe["column"]), t=ident(probe["table"]), k=ident(probe["key_column"]))
    return q + sql.SQL(" ORDER BY 1 DESC LIMIT 1") if order else q


def _consistency_checks(r: VerifyReport, cur, manifest: dict):
    probes = manifest.get("probes")
    if not probes:
        r.add("Сквозная консистентность (таблица+склейка+текст)", False,
              "проба не описана в манифесте канареек", skipped=True)
        r.add("Мягкая связь консистентна", False,
              "проба не описана в манифесте канареек", skipped=True)
        return

    identity = probes["identity"]        # где лежит эталонное значение личности
    cur.execute(_probe_sql(identity), (identity["key"],))
    row = cur.fetchone()
    fam = row[0] if row else None
    base = (fam or "").rstrip("а")       # женская форма в склейке «Канарейкина В.П.»
    seen = []
    for probe in probes.get("occurrences", []):
        cur.execute(_probe_sql(probe, order=True), (probe["key"],))
        got = cur.fetchone()
        text = got[0] if got else ""
        needle = base if probe.get("initials") else fam
        seen.append((probe["table"], bool(fam) and needle in (text or "")))
    r.add("Сквозная консистентность (таблица+склейка+текст)",
          bool(fam) and all(ok for _, ok in seen),
          f"эталон='{fam}'; " + ", ".join(f"{t}={'да' if ok else 'НЕТ'}" for t, ok in seen))

    # Целостность текста: то, что персональными данными не является, обязано
    # пережить санитизацию без изменений. Порчу экранированием не ловила ни одна
    # из восьми проверок - она вылезала уже на стороне потребителя копии.
    broken = []
    if not probes.get("preserved"):
        r.add("Текст не испорчен: не-ПДн фрагменты сохранены дословно", False,
              "проба не описана в манифесте канареек", skipped=True)
    for probe in probes.get("preserved", []):
        cur.execute(_probe_sql(probe), (probe["key"],))
        got = cur.fetchone()
        if not got or probe["substring"] not in (got[0] or ""):
            broken.append(f"{probe['table']}.{probe['column']}")
    if probes.get("preserved"):
        r.add("Текст не испорчен: не-ПДн фрагменты сохранены дословно", not broken,
              "; ".join(broken) if broken else f"{len(probes['preserved'])} проб целы")

    link = probes.get("soft_link")
    if not link:
        r.add("Мягкая связь консистентна", False, "проба не описана", skipped=True)
        return
    values = []
    for side in link["sides"]:
        cur.execute(_probe_sql(side), (side["key"],))
        got = cur.fetchone()
        values.append(got[0] if got else None)
    r.add("Мягкая связь консистентна", len(set(values)) == 1 and values[0] is not None,
          " == ".join(str(v) for v in values))


def _tables(cur, schema: str) -> list[str]:
    cur.execute("SELECT table_schema || '.' || table_name FROM information_schema.tables "
                "WHERE table_schema = %s AND table_type = 'BASE TABLE' ORDER BY 1", (schema,))
    return [r[0] for r in cur.fetchall()]


def _text_columns(cur, schema: str) -> dict[str, list[str]]:
    # список типов уезжает параметром, а не repr кортежа: прежняя склейка
    # работала случайно и на кортеже из одного элемента давала «('text',)»
    cur.execute("SELECT table_schema || '.' || table_name, column_name "
                "FROM information_schema.columns WHERE table_schema = %s "
                "AND data_type = ANY(%s)", (schema, list(_TEXTLIKE)))
    out: dict[str, list[str]] = {}
    for t, c in cur.fetchall():
        out.setdefault(t, []).append(c)
    return out


def _primary_keys(cur, schema: str) -> dict[str, list[str]]:
    """Таблица -> колонки первичного ключа. Заменяет зашитый «id» и спецкейс
    демонстрационной hr.contract_items."""
    cur.execute(
        "SELECT tc.table_schema || '.' || tc.table_name, kcu.column_name "
        "FROM information_schema.table_constraints tc "
        "JOIN information_schema.key_column_usage kcu "
        "  ON kcu.constraint_name = tc.constraint_name "
        " AND kcu.table_schema = tc.table_schema AND kcu.table_name = tc.table_name "
        "WHERE tc.table_schema = %s AND tc.constraint_type = 'PRIMARY KEY' "
        "ORDER BY kcu.ordinal_position", (schema,))
    out: dict[str, list[str]] = {}
    for t, c in cur.fetchall():
        out.setdefault(t, []).append(c)
    return out


def _pk_expr(pk_of: dict[str, list[str]], table: str):
    """Ключ строки для построчной сверки. Разделитель - управляющий символ, а не
    «/»: склейка через печатный разделитель давала коллизии («a/b»+«c» и «a»+«b/c»)
    и сверка молча теряла нарушения."""
    from psycopg import sql

    cols = pk_of.get(table) or []
    if not cols:
        raise ValueError(f"{table}: нет первичного ключа - построчная сверка невозможна")
    return sql.SQL("concat_ws(chr(1), {})").format(
        sql.SQL(", ").join(sql.SQL("{}::text").format(ident(c)) for c in cols))


def _found_anywhere(cur, text_cols: dict[str, list[str]], needle: str) -> bool:
    for table, cols in text_cols.items():
        from psycopg import sql

        conds = sql.SQL(" OR ").join(sql.SQL("{}::text ILIKE %s").format(ident(c)) for c in cols)
        cur.execute(sql.SQL("SELECT 1 FROM {} WHERE {} LIMIT 1").format(ident(table), conds),
                    [f"%{needle}%"] * len(cols))
        if cur.fetchone():
            return True
    return False


def _col_by_pk(cur, table: str, col: str, pk_expr) -> dict:
    from psycopg import sql

    cur.execute(sql.SQL("SELECT {k}, {c}::text FROM {t}")
                .format(k=pk_expr, c=ident(col), t=ident(table)))
    return dict(cur.fetchall())


def _col_entropy(cur, table: str, col: str) -> float:
    from psycopg import sql

    cur.execute(sql.SQL("SELECT count(*) FROM {t} GROUP BY {c}").format(t=ident(table), c=ident(col)))
    return entropy([r[0] for r in cur.fetchall()])


_FK_COUNT = ("SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
             "WHERE c.contype IN ('f','u','p') AND t.relnamespace::regnamespace::text = %s")


def column_checksums(dsn: str, plan: Plan, schema: str | None = None) -> dict[str, str]:
    """Поколоночные md5 для сравнения двух прогонов (§7 воспроизводимость).
    Свободнотекстовые колонки включаются только при перенесённом кэше."""
    import psycopg
    from psycopg import sql

    schema = schema or sorted({q.split(".", 1)[0] for q in plan.columns})[0]
    out: dict[str, str] = {}
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        pk_of = _primary_keys(cur, schema)
        for qualified, pc in plan.columns.items():
            if pc.strategy in ("keep", "unresolved"):
                continue
            table, col = qualified.rsplit(".", 1)
            order = sql.SQL(", ").join(ident(c) for c in (pk_of.get(table) or [col]))
            cur.execute(sql.SQL("SELECT md5(string_agg({c}::text, '' ORDER BY {o})) FROM {t}")
                        .format(c=ident(col), o=order, t=ident(table)))
            out[qualified] = cur.fetchone()[0] or ""
    return out




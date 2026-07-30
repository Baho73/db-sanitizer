# START_MODULE_CONTRACT
#   PURPOSE: Демонстрационный отчёт «до/после»: сопоставление образцов исходной
#            и санитизированной баз, сводка плана, доказательства консистентности.
#   SCOPE: Только чтение обеих БД и плана; статический HTML/Markdown на выход.
#   DEPENDS: M-POLICY, M-VERIFIER
#   LINKS: V-M-CLI, docs/solution-design.md §7
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   build_report - собрать данные сравнения
#   render_html - самодостаточная страница стенда
# END_MODULE_MAP
from __future__ import annotations

import html
import json
from pathlib import Path

from sanitizer.policy import Plan

SAMPLE_SQL = {
    "Сотрудники (ФИО, ИНН, СНИЛС, телефон, email)": (
        "SELECT id, last_name, first_name, middle_name, inn, snils, phone, email "
        "FROM hr.employees WHERE id IN (1, 2, 3, %(canary)s) ORDER BY id"),
    "Адреса (в т.ч. грязная строка с посторонним хвостом)": (
        "SELECT id, addr_text FROM hr.addresses WHERE id IN (1, 2, %(canary)s) ORDER BY id"),
    "Свободный текст заявок": (
        "SELECT id, body_text FROM hr.tickets WHERE id IN (1, 2, %(ticket)s) ORDER BY id"),
    "Комментарии со склейкой «ФИО, тел.»": (
        "SELECT id, comment_text FROM hr.ticket_comments ORDER BY id DESC LIMIT 3"),
    "Контрагенты (мягкая связь по ИНН, город с полным адресом)": (
        "SELECT id, name, inn, city FROM hr.contractors ORDER BY id DESC LIMIT 3"),
    "JSONB с ПДн внутри": (
        "SELECT id, attrs::text FROM hr.employees WHERE id IN (1, %(canary)s) ORDER BY id"),
}


def build_report(src_dsn: str, dst_dsn: str, plan: Plan, canary_manifest: Path) -> dict:
    import psycopg

    manifest = json.loads(canary_manifest.read_text(encoding="utf-8"))
    params = {"canary": manifest["employee_id"], "ticket": manifest["ticket_id"]}
    out: dict = {"blocks": [], "plan_summary": {}, "counts": {}}

    with psycopg.connect(src_dsn) as src, psycopg.connect(dst_dsn) as dst:
        s, d = src.cursor(), dst.cursor()
        for title, sql in SAMPLE_SQL.items():
            s.execute(sql, params)
            before = s.fetchall()
            cols = [c.name for c in s.description]
            d.execute(sql, params)
            after = d.fetchall()
            out["blocks"].append({"title": title, "columns": cols,
                                  "before": [list(map(_str, r)) for r in before],
                                  "after": [list(map(_str, r)) for r in after]})
        for t in ("hr.employees", "hr.addresses", "hr.tickets", "hr.ticket_comments",
                  "hr.contractors", "hr.payroll"):
            s.execute(f"SELECT count(*) FROM {t}")
            d.execute(f"SELECT count(*) FROM {t}")
            out["counts"][t] = (s.fetchone()[0], d.fetchone()[0])

    for pc in plan.columns.values():
        out["plan_summary"][pc.strategy] = out["plan_summary"].get(pc.strategy, 0) + 1
    return out


def _str(v) -> str:
    return "" if v is None else str(v)


def render_html(data: dict, verify_md: str, dump_md: str, title: str) -> str:
    def table(block) -> str:
        head = "".join(f"<th>{html.escape(c)}</th>" for c in block["columns"])
        rows = []
        for kind, label in (("before", "до"), ("after", "после")):
            for r in block[kind]:
                cells = "".join(f"<td>{html.escape(x)}</td>" for x in r)
                rows.append(f'<tr class="{kind}"><td class="lbl">{label}</td>{cells}</tr>')
        return (f'<h3>{html.escape(block["title"])}</h3><div class="scroll"><table>'
                f"<tr><th></th>{head}</tr>{''.join(rows)}</table></div>")

    counts = "".join(
        f"<tr><td>{html.escape(t)}</td><td>{a}</td><td>{b}</td>"
        f'<td>{"✅" if a == b else "❌"}</td></tr>'
        for t, (a, b) in data["counts"].items())
    strategies = "".join(f"<tr><td><code>{html.escape(k)}</code></td><td>{v}</td></tr>"
                         for k, v in sorted(data["plan_summary"].items(), key=lambda x: -x[1]))
    blocks = "".join(table(b) for b in data["blocks"])
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>
:root{{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e3e3e3;--b:#fff5f5;--a:#f2fbf4;--acc:#0b6b3a}}
@media(prefers-color-scheme:dark){{:root{{--bg:#15171a;--fg:#e8e8e8;--mut:#9aa0a6;--line:#2c3036;--b:#2a1e1e;--a:#16261c;--acc:#7ee2a8}}}}
*{{box-sizing:border-box}}body{{margin:0;padding:2rem 1rem;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:1100px;margin:0 auto}}h1{{font-size:1.6rem;margin:0 0 .3rem}}
h2{{margin:2.2rem 0 .6rem;font-size:1.2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}}
h3{{margin:1.4rem 0 .4rem;font-size:.98rem;color:var(--mut);font-weight:600}}
p.sub{{color:var(--mut);margin:0 0 1.5rem}}
.scroll{{overflow-x:auto;-webkit-overflow-scrolling:touch}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:.5rem}}
th,td{{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top;
white-space:nowrap;max-width:34ch;overflow:hidden;text-overflow:ellipsis}}
th{{background:var(--line);font-weight:600}}
tr.before td{{background:var(--b)}}tr.after td{{background:var(--a)}}
td.lbl{{font-weight:700;color:var(--mut);white-space:nowrap}}
code{{background:var(--line);padding:.1rem .3rem;border-radius:3px;font-size:.9em}}
.md table{{white-space:normal}}.md td{{white-space:normal;max-width:none}}
footer{{margin-top:3rem;color:var(--mut);font-size:13px;border-top:1px solid var(--line);padding-top:1rem}}
a{{color:var(--acc)}}
</style></head><body><main>
<h1>{html.escape(title)}</h1>
<p class="sub">Стенд демонстрации: обезличивание PostgreSQL-базы с сохранением связей,
объёма и разнообразия. Красным — исходные данные, зелёным — санитизированная копия.</p>

<h2>1. Сопоставление «до / после»</h2>
{blocks}

<h2>2. Объём сохранён</h2>
<div class="scroll"><table><tr><th>Таблица</th><th>Строк до</th><th>Строк после</th><th></th></tr>
{counts}</table></div>

<h2>3. Критерии приёмки — прогон через подключение</h2>
<div class="md scroll">{verify_md}</div>

<h2>4. Критерии приёмки — прогон из дампа (второй вход по ТЗ)</h2>
<div class="md scroll">{dump_md}</div>

<h2>5. Стратегии в плане санитизации</h2>
<div class="scroll"><table><tr><th>Стратегия</th><th>Колонок</th></tr>{strategies}</table></div>

<footer>Данные синтетические (Faker + LLM-корпуса), реальных персональных данных не содержат.<br>
Проектный документ, разборы и код — в репозитории проекта.</footer>
</main></body></html>"""


def md_table_to_html(md: str) -> str:
    rows = [r for r in md.strip().splitlines() if r.startswith("|")]
    out = ["<table>"]
    for i, r in enumerate(rows):
        cells = [c.strip() for c in r.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        tag = "th" if i == 0 else "td"
        out.append("<tr>" + "".join(f"<{tag}>{html.escape(c)}</{tag}>" for c in cells) + "</tr>")
    out.append("</table>")
    return "".join(out)

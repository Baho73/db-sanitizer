# START_MODULE_CONTRACT
#   PURPOSE: CLI: plan / run / restore / verify / demo-seed. Сообщения fail-closed
#            называют колонку, причину и следующий шаг (ux-guidelines).
#   SCOPE: Склейка модулей; логики замен не содержит.
#   DEPENDS: все модули конвейера
#   LINKS: V-M-CLI
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   main - argparse-диспетчер подкоманд
#   DEF_COMPONENTS - путь к компонентам корпусов по умолчанию
#   cmd_demo_seed - посев демо-базы
#   cmd_plan - фаза планирования с гейтом
#   cmd_run - исполнение: проход 1 и проход 2
#   cmd_restore - разворачивание дампа в staging вместе со схемой sanitization
#   cmd_verify - верификация и блокировка публикации
#   cmd_report - сборка страницы стенда «до/после»
# END_MODULE_MAP
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import Salt
from sanitizer.policy import Plan
from sanitizer.runlog import RunLog

DEF_COMPONENTS = "sanitizer/data/components-ru.json"


def _salt() -> Salt:
    # os.environb только на POSIX - на Windows CLI падал бы при старте
    return Salt(master=os.environ.get("MASTER_SALT", "dev-master").encode(),
                recipient=os.environ.get("RECIPIENT", "dev"),
                generation=os.environ.get("GENERATION", "g1"),
                version=int(os.environ.get("MASTER_SALT_VERSION", "1")))


def cmd_demo_seed(a) -> int:
    from sanitizer.demo.seed import seed_db

    counts = seed_db(a.dsn, a.scale, canary_path=Path(a.out) / "canaries.json")
    print(json.dumps(counts, indent=1))
    return 0


def cmd_plan(a) -> int:
    from sanitizer.plan_graph import build_graph, run_planning

    cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
    state = {"dsn": a.dsn, "schema": "hr", "llm_cache": a.llm_cache,
             "json_map": cfg.get("json_map", {}),
             "sensitive_categories": cfg.get("sensitive_categories", []),
             "overrides": cfg.get("overrides", {}),
             "confirm": cfg.get("confirm", []),
             "plan_path": a.plan, "auto_approve": a.auto_approve}
    try:
        out = run_planning(build_graph(), state)
    except ValueError as e:  # запрещённый override - решение человека вне гейта
        print(f"КОНФИГ ОТКЛОНЁН (fail-closed): {e}")
        return 1
    if "__interrupt__" in out:
        payload = out["__interrupt__"][0].value
        print("ГЕЙТ: план ждёт аппрува.")
        print(f"  Черновик: {payload['plan_draft']}")
        print(f"  Дифф: {payload['diff'] or 'первый прогон'}")
        for e in payload["validation_errors"]:
            print(f"  БЛОКЕР: {e}")
        print("Дальше: проверьте черновик и запустите с --auto-approve "
              "либо задайте решения в plan-config.json (overrides).")
        return 2
    if out.get("errors"):
        print("ПЛАН ОТКЛОНЁН ВАЛИДАЦИЕЙ (fail-closed):")
        for e in out["errors"]:
            print(f"  {e}")
        return 1
    print(f"План записан: {a.plan}")
    return 0


def cmd_run(a) -> int:
    from sanitizer.executor import run_pass1
    from sanitizer.postproc import TextSanitizer, process_dump
    from sanitizer.mapper import Mapper
    from sanitizer.profiler import profile

    plan = Plan.load(Path(a.plan))
    salt = _salt()
    corpora = build_corpora(load_components(Path(a.components)))
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    rl = RunLog(work / "runlog.db")
    run_id = rl.start_run(plan.schema_fingerprint, salt.recipient, salt.generation,
                          master_salt_version=salt.version)
    print(f"run_id={run_id}")

    # снапшот порядка колонок и словарь имён источника - для прохода 2
    snap = profile(a.dsn, "hr")
    columns_order: dict[str, list[str]] = {}
    for c in snap.columns:
        columns_order.setdefault(c.table, []).append(c.name)
    name_dict = _source_name_dict(a.dsn)

    dump_dir = run_pass1(plan, a.dsn, salt, corpora, work, rl, run_id,
                         greenmask_bin=a.greenmask, plan_path=Path(a.plan))
    print(f"проход 1 завершён: {dump_dir}")

    ts = TextSanitizer(Mapper(salt, corpora), salt, name_dict)
    summary = process_dump(dump_dir, plan, columns_order, ts, runlog=rl)
    print(f"проход 2 завершён: {json.dumps(summary, ensure_ascii=False)}")
    (work / "run_id").write_text(run_id, encoding="utf-8")
    (work / "dump_path").write_text(str(dump_dir), encoding="utf-8")
    return 0


def _resolve_dump(path: Path) -> Path:
    if (path / "toc.dat").exists():
        return path
    subdirs = [p for p in path.iterdir() if p.is_dir() and p.name.isdigit()]
    if not subdirs:
        raise SystemExit(f"в {path} нет валидного дампа (toc.dat)")
    return max(subdirs, key=lambda p: int(p.name))


def _source_name_dict(dsn: str) -> frozenset[str]:
    """Словарь ФИО источника для точного NER (§5.5); живёт в контуре."""
    import psycopg

    words: set[str] = set()
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        for col in ("last_name", "first_name", "middle_name"):
            cur.execute(f"SELECT DISTINCT {col} FROM hr.employees WHERE {col} IS NOT NULL")
            words |= {r[0].lower().replace("ё", "е") for r in cur.fetchall()}
    return frozenset(words)


def cmd_restore(a) -> int:
    dump = _resolve_dump(Path(a.dump))
    env = {**os.environ, "PGPASSWORD": a.password}
    subprocess.run([a.pg_restore, "--clean", "--if-exists", "--no-owner",
                    "-h", a.host, "-p", str(a.port), "-U", a.user, "-d", a.db,
                    str(dump)], check=True, env=env)
    san = dump / "sanitization.sql"
    if san.exists():  # примечания §5.7.1 едут внутри каталога дампа
        subprocess.run([a.psql, "-h", a.host, "-p", str(a.port), "-U", a.user,
                        "-d", a.db, "-q", "-f", str(san)], check=True, env=env)
    print("restore завершён (включая схему sanitization)")
    return 0


def cmd_verify(a) -> int:
    from sanitizer.verifier import column_checksums, render_markdown, verify

    plan = Plan.load(Path(a.plan))
    work = Path(a.work)
    rl = RunLog(work / "runlog.db")
    run_id = (work / "run_id").read_text(encoding="utf-8").strip()
    rl.meta = {"run_id": run_id, "plan_version": plan.schema_fingerprint,
               "master_salt_version": _salt().version, "salt_generation": _salt().generation,
               "recipient_id": _salt().recipient, "corpus_version": "fixtures-1",
               "cache_version": "none", "tool_version": "0.1.0"}
    rl.mark("verify", "*", "running")
    report = verify(a.src_dsn, a.dst_dsn, plan, Path(a.canaries))
    md = render_markdown(report)
    Path(a.report).write_text(md, encoding="utf-8")
    checks = column_checksums(a.dst_dsn, plan)
    Path(a.report).with_suffix(".checksums.json").write_text(
        json.dumps(checks, indent=1), encoding="utf-8")
    print(md)
    if not report.ok:
        rl.mark("verify", "*", "failed")
        print("ВЕРИФИКАЦИЯ ПРОВАЛЕНА - публикация дампа заблокирована (run_log)")
        return 1
    rl.mark("verify", "*", "done")
    print(f"Публикация разрешена: publishable={rl.publishable(run_id)}")
    return 0


def cmd_report(a) -> int:
    from sanitizer.report import build_report, md_table_to_html, render_html

    plan = Plan.load(Path(a.plan))
    data = build_report(a.src_dsn, a.dst_dsn, plan, Path(a.canaries))
    verify_md = Path(a.verify).read_text(encoding="utf-8") if Path(a.verify).exists() else ""
    dump_md = Path(a.verify_dump).read_text(encoding="utf-8") if Path(a.verify_dump).exists() else ""
    page = render_html(data, md_table_to_html(verify_md), md_table_to_html(dump_md), a.title)
    Path(a.out).write_text(page, encoding="utf-8")
    print(f"стенд собран: {a.out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser("sanitizer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("demo-seed")
    p.add_argument("--dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    p.add_argument("--scale", default="small")
    p.add_argument("--out", default="out")
    p.set_defaults(fn=cmd_demo_seed)

    p = sub.add_parser("plan")
    p.add_argument("--dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    p.add_argument("--config", default="sanitizer/demo/plan-config.json")
    p.add_argument("--llm-cache", default="tests/fixtures/llm_votes_demo.json")
    p.add_argument("--plan", default="out/sanitization-plan.yaml")
    p.add_argument("--auto-approve", action="store_true")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("run")
    p.add_argument("--dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    p.add_argument("--plan", default="out/sanitization-plan.yaml")
    p.add_argument("--components", default=DEF_COMPONENTS)
    p.add_argument("--work", default="out")
    p.add_argument("--greenmask", default=os.environ.get("GREENMASK_BIN", "greenmask"))
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("restore")
    p.add_argument("--dump", default="out/dump")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=55433)
    p.add_argument("--user", default="staging")
    p.add_argument("--password", default="staging")
    p.add_argument("--db", default="staging")
    p.add_argument("--pg-restore", default="pg_restore")
    p.add_argument("--psql", default="psql")
    p.set_defaults(fn=cmd_restore)

    p = sub.add_parser("verify")
    p.add_argument("--src-dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    p.add_argument("--dst-dsn", default=os.environ.get("STAGING_DSN", "postgresql://staging:staging@127.0.0.1:55433/staging"))
    p.add_argument("--plan", default="out/sanitization-plan.yaml")
    p.add_argument("--canaries", default="out/canaries.json")
    p.add_argument("--work", default="out")
    p.add_argument("--report", default="out/verify-report.md")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("report")
    p.add_argument("--src-dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    p.add_argument("--dst-dsn", default=os.environ.get("STAGING_DSN", "postgresql://staging:staging@127.0.0.1:55433/staging"))
    p.add_argument("--plan", default="out/sanitization-plan.yaml")
    p.add_argument("--canaries", default="out/canaries.json")
    p.add_argument("--verify", default="out/verify-report.md")
    p.add_argument("--verify-dump", default="out/verify-dump.md")
    p.add_argument("--out", default="out/stand/index.html")
    p.add_argument("--title", default="Санитизация БД — демонстрация «до/после»")
    p.set_defaults(fn=cmd_report)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

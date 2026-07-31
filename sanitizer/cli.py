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
#   cmd_approve - продолжение после гейта другой командой (персистентный чекпойнт)
#   cmd_run - исполнение: проход 1 и проход 2
#   cmd_restore - разворачивание дампа в staging вместе со схемой sanitization
#   cmd_verify - верификация и блокировка публикации
#   cmd_publish - вынос дампа из рабочего каталога только при разрешении журнала
#   cmd_report - сборка страницы стенда «до/после»
# END_MODULE_MAP
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from sanitizer.corpus import build_corpora, corpus_limits, load_components, validate_corpus
from sanitizer.mapper import Salt
from sanitizer.policy import Plan, validate_plan
from sanitizer.runlog import RunLog

DEF_COMPONENTS = "sanitizer/data/components-ru.json"


def _salt() -> Salt:
    # os.environb только на POSIX - на Windows CLI падал бы при старте.
    # Умолчания у MASTER_SALT нет: соль - единственный секрет системы, и молчаливый
    # публично известный дефолт означал бы обратимое обезличивание без единого
    # предупреждения (разбор 4, таблица свойств: детерминизм).
    master = os.environ.get("MASTER_SALT")
    if not master:
        raise SystemExit(
            "MASTER_SALT не задан. Соль - единственный секрет инструмента: без неё "
            "замены воспроизводит кто угодно.\nДальше: возьмите значение из "
            "секрет-стора и экспортируйте MASTER_SALT, затем повторите команду. "
            "Подсказывать значение здесь нельзя: подсказанная соль перестаёт быть секретом.")
    return Salt(master=master.encode(),
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
    graph = build_graph(Path(a.checkpoint))
    gcfg = {"configurable": {"thread_id": a.thread}}
    if graph.get_state(gcfg).next:
        # Повторный plan на треде с висящим гейтом молча перезапускал граф с
        # START и перезаписывал и чекпойнт, и черновик - а approve потом
        # подписывал НЕ ТО, что человек читал (ревью 2, Н4). Отказ, а не
        # молчаливая подмена.
        print(f"ОТКАЗ: прогон {a.thread!r} уже остановлен на гейте и ждёт решения.")
        print("Дальше: sanitizer approve --thread ... [--confirm ...] или "
              "--reject; новое планирование - под другим --thread.")
        return 1
    state = {"dsn": a.dsn, "schema": a.schema, "llm_cache": a.llm_cache,
             "llm_available": bool(cfg.get("llm_available")),
             "json_map": cfg.get("json_map", {}),
             "sensitive_categories": cfg.get("sensitive_categories", []),
             "overrides": cfg.get("overrides", {}),
             "confirm": cfg.get("confirm", []),
             "params": cfg.get("params", {}),
             "plan_path": a.plan, "auto_approve": a.auto_approve}
    try:
        out = run_planning(graph, state, thread_id=a.thread)
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
        print("Дальше: прочитайте черновик и подтвердите решение человека:")
        print(f"  sanitizer approve --thread {a.thread} "
              f"[--confirm колонка ...] [--reject]")
        print("  (разметку колонок задавайте в plan-config.json, overrides)")
        return 2
    if out.get("errors"):
        print("ПЛАН ОТКЛОНЁН ВАЛИДАЦИЕЙ (fail-closed):")
        for e in out["errors"]:
            print(f"  {e}")
        return 1
    print(f"План записан: {a.plan}")
    return 0


# START_CONTRACT: cmd_approve
#   PURPOSE: Продолжение остановленного на гейте планирования ДРУГОЙ командой,
#            возможно через сутки и из другого процесса. Ради этого свойства и
#            выбирался LangGraph; с чекпойнтером в памяти оно не работало.
#   INPUTS: { checkpoint: файл состояния, thread: идентификатор прогона,
#             confirm: колонки, подтверждаемые человеком, reject: отклонить план }
#   OUTPUTS: { 0 - план записан; 1 - отклонён или заблокирован валидацией }
#   SIDE_EFFECTS: запись плана, обновление чекпойнта
# END_CONTRACT: cmd_approve
def cmd_approve(a) -> int:
    from langgraph.types import Command

    from sanitizer.plan_graph import build_graph

    graph = build_graph(Path(a.checkpoint))
    cfg = {"configurable": {"thread_id": a.thread}}
    gstate = graph.get_state(cfg)
    if not gstate.next:
        print(f"Нечего подтверждать: прогон {a.thread!r} не остановлен на гейте.")
        print("Дальше: запустите sanitizer plan, он остановится и назовёт черновик.")
        return 1
    # Привязка к прочитанному (ревью 2, Н4): черновик на диске мог быть
    # перезаписан после показа человеку - approve подписывает только тот
    # черновик, чей хэш зафиксирован в нагрузке гейта.
    payload = gstate.tasks[0].interrupts[0].value
    expected = payload.get("draft_sha256", "")
    draft = Path(payload["plan_draft"])
    actual = hashlib.sha256(draft.read_bytes()).hexdigest() if draft.exists() else ""
    if expected and actual != expected:
        print("ОТКАЗ: черновик на диске изменился после показа на гейте")
        print(f"  ({draft}). Подтвердить можно только прочитанную версию.")
        print("Дальше: --reject и новое планирование, либо перечитайте и "
              "сверьте изменения.")
        return 1
    answer = {"approve": not a.reject, "confirm": list(a.confirm or [])}
    out = graph.invoke(Command(resume=answer), cfg)
    if a.reject:
        print("План ОТКЛОНЁН человеком; файл плана не записан.")
        return 1
    if out.get("errors"):
        print("ПЛАН ОТКЛОНЁН ВАЛИДАЦИЕЙ (fail-closed):")
        for e in out["errors"]:
            print(f"  {e}")
        return 1
    print(f"Подтверждено человеком. План записан: {out.get('plan_path', 'см. --plan')}")
    return 0


# START_CONTRACT: _resume_or_start_run
#   PURPOSE: run_id прогона: возобновить прерванный либо начать новый. Без
#            возобновления каждый перезапуск CLI порождал новый run_id, журнал
#            прошлого прогона для _completed_tables был пуст - и проход 2
#            обрабатывал уже санитизированные таблицы второй раз (ревью 2, Н1).
#   INPUTS: { rl: RunLog, work: каталог прогона, plan, salt }
#   OUTPUTS: { str - run_id }
#   SIDE_EFFECTS: SystemExit при висячем прогоне с чужими отпечатками
# END_CONTRACT: _resume_or_start_run
def _resume_or_start_run(rl: RunLog, work: Path, plan: Plan, salt: Salt) -> str:
    rid_file = work / "run_id"
    if rid_file.exists():
        rid = rid_file.read_text(encoding="utf-8").strip()
        meta = rl.run_meta(rid)
        if meta and not rl.publishable(rid):
            current = {"plan_version": plan.schema_fingerprint,
                       "master_salt_version": salt.version,
                       "salt_generation": salt.generation,
                       "recipient_id": salt.recipient}
            if meta == current:
                print(f"возобновляю прерванный прогон run_id={rid}")
                rl.meta = {"run_id": rid, **current, "corpus_version": "fixtures-1",
                           "cache_version": "none", "tool_version": "0.1.0"}
                return rid
            # Продолжить чужой прогон нельзя (соль/план другие - замены не
            # сойдутся), затереть его молча - тоже: это чей-то незаконченный run.
            raise SystemExit(
                f"В {work} висит прерванный прогон {rid} с ДРУГИМИ отпечатками "
                f"плана/соли (журнал: {meta}).\nДальше: либо верните тот план и "
                f"соль и повторите run (прогон возобновится), либо очистите "
                f"рабочий каталог / задайте другой --work.")
    return rl.start_run(plan.schema_fingerprint, salt.recipient, salt.generation,
                        master_salt_version=salt.version)


def _read_run_file(work: Path, name: str) -> str:
    """Файл-маркер прогона. Отсутствие - это «run ещё не было», а не повод
    уронить команду traceback'ом (ревью 2, UX fail-closed)."""
    f = work / name
    if not f.exists():
        raise SystemExit(f"в {work} нет {name} - прогон run ещё не выполнялся "
                         f"или выполнялся с другим --work.\nДальше: сначала run.")
    return f.read_text(encoding="utf-8").strip()


def cmd_run(a) -> int:
    from sanitizer.executor import run_pass1
    from sanitizer.postproc import TextSanitizer, process_dump
    from sanitizer.mapper import Mapper
    from sanitizer.profiler import profile

    from sanitizer import llm as llm_mod

    plan = Plan.load(Path(a.plan))
    salt = _salt()
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)

    # Поставщик модели опционален во всех трёх ролях исполнения. Его отсутствие -
    # не ошибка: конвейер обязан отрабатывать по кэшу и словарям, иначе
    # проверяющий не сможет повторить прогон без своей модели.
    client = llm_mod.from_env()
    if client:
        print(f"LLM: {client.provider}/{client.model} на {client.base_url}"
              f"{'' if client.sees_personal_data else ' (вне контура: свободный текст ей не показывается)'}")
    corpora = build_corpora(_components(a, client))

    # снапшот порядка колонок и словарь имён источника - для прохода 2
    snap = profile(a.dsn, a.schema)
    columns_order: dict[str, list[str]] = {}
    for c in snap.columns:
        columns_order.setdefault(c.table, []).append(c.name)

    # корпуса проверяются ДО прогона: непроверенный материал замен - это данные,
    # которые уедут в staging. Предел длины берётся из колонок-потребителей.
    limits = corpus_limits({q: pc.sem_type for q, pc in plan.columns.items()
                            if pc.strategy == "fake"},
                           {c.qualified: c.max_len for c in snap.columns})
    problems = validate_corpus(corpora, limits)
    if problems:
        print("КОРПУС ОТКЛОНЁН (fail-closed) - материал замен негоден:")
        for p in problems:
            print(f"  {p}")
        print("Дальше: почините компоненты корпуса и повторите run.")
        return 1

    # План проверяется ПЕРЕД исполнением, а не только при составлении: колонка,
    # добавленная после аппрува, или план, отредактированный руками, иначе уехали
    # бы в дамп сырыми - greenmask_config строит трансформации только по плану.
    # §3.5 обещает «колонки нет в плане -> прогон не стартует»; вот это обещание.
    errors = validate_plan(plan, snap)
    if errors:
        print("ПЛАН НЕ ПРИМЕНИМ К ТЕКУЩЕЙ СХЕМЕ (fail-closed):")
        for e in errors:
            print(f"  {e}")
        print("Дальше: перепланируйте (sanitizer plan) и проведите план через гейт.")
        return 1

    rl = RunLog(work / "runlog.db")
    run_id = _resume_or_start_run(rl, work, plan, salt)
    print(f"run_id={run_id}")
    name_dict = _source_name_dict(a.dsn, a.schema)

    dump_dir = run_pass1(plan, a.dsn, salt, corpora, work, rl, run_id,
                         greenmask_bin=a.greenmask, plan_path=Path(a.plan),
                         llm=_direct_llm(client, plan))
    print(f"проход 1 завершён: {dump_dir}")

    # Третий эшелон NER видит ЖИВОЙ текст, поэтому допускается только модель в
    # контуре. Кэш вердиктов - версионируемый артефакт (§4.4): повторный прогон
    # на том же тексте не обращается к модели и даёт тот же результат.
    ner_cache_path = work / "ner-cache.json"
    ner_cache = json.loads(ner_cache_path.read_text(encoding="utf-8")) \
        if ner_cache_path.exists() else {}
    ts = TextSanitizer(Mapper(salt, corpora), salt, name_dict,
                       llm=_ner_llm(client), llm_cache=ner_cache)
    summary = process_dump(dump_dir, plan, columns_order, ts, runlog=rl,
                           max_len={c.qualified: c.max_len for c in snap.columns})
    ner_cache_path.write_text(json.dumps(ts.llm_cache, ensure_ascii=False, indent=1),
                              encoding="utf-8")
    if client:
        print(f"обращений к модели: {len(client.calls)} ({', '.join(sorted(set(client.calls)))})")
    print(f"проход 2 завершён: {json.dumps(summary, ensure_ascii=False)}")
    (work / "run_id").write_text(run_id, encoding="utf-8")
    (work / "dump_path").write_text(str(dump_dir), encoding="utf-8")
    return 0


# START_CONTRACT: _components
#   PURPOSE: Компоненты корпусов: от модели с кэшем на диске либо из поставляемых
#            словарей. Роль 2 не видит ни одного настоящего значения - модель
#            порождает материал замен с нуля (§4.4).
#   INPUTS: { a: аргументы CLI, client: LLMClient|None }
#   OUTPUTS: { dict ключ корпуса -> список значений }
#   SIDE_EFFECTS: чтение/запись кэша корпусов, сетевые вызовы при первом прогоне
# END_CONTRACT: _components
def _components(a, client) -> dict[str, list[str]]:
    from sanitizer import llm as llm_mod
    from sanitizer.corpus import REQUIRED_KEYS, llm_components

    raw = (getattr(a, "corpus_cache", "") or "").strip()
    if client is None or not raw:      # Path("") == Path(".") - проверять надо строку
        return load_components(Path(a.components))
    cache = Path(raw)
    if not cache.exists():
        print(f"корпуса: порождаю моделью, кэш {cache}")
    data = llm_components(cache, generate=lambda kind: llm_mod.corpus_generate(client, kind))
    missing = [k for k in REQUIRED_KEYS if not data.get(k)]
    if missing:
        raise SystemExit(f"КОРПУС ОТ МОДЕЛИ НЕПОЛОН: нет {missing}. "
                         f"Дальше: удалите {cache} и повторите либо снимите --corpus-cache.")
    return data


def _direct_llm(client, plan):
    """Роль 3: карта 1:1 для не-ПДн значений. None, если поставщик не настроен.

    Колонка с llm_mode != "direct" в аппрувнутом плане модель не обслуживает
    даже при настроенном поставщике: исполнение не должно молча расходиться с
    планом, прошедшим гейт (ревью 2, §6.11 п.3). Пустая карта здесь означает
    «модель не участвовала» - значения достраивает corpus-fallback."""
    from sanitizer import llm as llm_mod

    if client is None:
        return None

    def call(qualified, values):
        pc = plan.columns.get(qualified)
        if pc is None or pc.llm_mode != "direct":
            return {}
        return llm_mod.direct_map(client, values)

    return call


def _ner_llm(client):
    """Роль 4: вердикт по спорному фрагменту. Только модель в контуре - иначе
    инструмент обезличивания сам отправит персональные данные наружу.

    Перед прогоном модель проходит приёмку: роль 4 - защитный механизм, и
    негодная модель понижает защиту МОЛЧА. Замерено: mistral-nemo:12b отвечает
    «нет» на «Мария Сидорова», то есть оставляет ФИО в копии без отметки."""
    from sanitizer import llm as llm_mod

    if client is None or not client.sees_personal_data:
        return None
    ok, report = llm_mod.ner_acceptance(client)
    if not ok:
        print(f"МОДЕЛЬ {client.model} НЕ ПРИНЯТА на роль NER: {report}")
        print("Свободный текст обрабатывается без неё; неразобранные фрагменты "
              "получат отметку low_confidence_ner и попадут в порог max_degraded.")
        return None
    print(f"приёмка модели на роль NER: {report}")
    return lambda fragment: llm_mod.ner_verdict(client, fragment)


def _resolve_dump(path: Path) -> Path:
    if (path / "toc.dat").exists():
        return path
    subdirs = [p for p in path.iterdir() if p.is_dir() and p.name.isdigit()]
    if not subdirs:
        raise SystemExit(f"в {path} нет валидного дампа (toc.dat)")
    return max(subdirs, key=lambda p: int(p.name))


def _source_name_dict(dsn: str, schema: str = "hr") -> frozenset[str]:
    """Словарь ФИО источника для точного NER (§5.5); живёт в контуре.
    Собирается по всем колонкам схемы с именами компонент ФИО, а не по одной
    зашитой таблице: на чужой базе employees может не быть вовсе."""
    import psycopg

    words: set[str] = set()
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT table_schema || '.' || table_name, column_name "
            "FROM information_schema.columns WHERE table_schema = %s "
            "AND column_name IN ('last_name','first_name','middle_name','patronymic')",
            (schema,))
        from psycopg import sql

        from sanitizer.profiler import ident
        for table, col in cur.fetchall():
            cur.execute(sql.SQL("SELECT DISTINCT {c} FROM {t} WHERE {c} IS NOT NULL")
                        .format(c=ident(col), t=ident(table)))
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
    run_id = _read_run_file(work, "run_id")
    salt = _salt()
    meta = {"run_id": run_id, "plan_version": plan.schema_fingerprint,
            "master_salt_version": salt.version, "salt_generation": salt.generation,
            "recipient_id": salt.recipient, "corpus_version": "fixtures-1",
            "cache_version": "none", "tool_version": "0.1.0"}
    # Verify обязан относиться к ЭТОМУ прогону: журнал согласен опубликовать
    # что угодно, если verify=done записан под тем же run_id - даже от проверки
    # чужим планом, другой солью или для другого получателя (ревью 2, Н5).
    recorded = rl.run_meta(run_id)
    if recorded is not None and recorded != {k: meta[k] for k in recorded}:
        print(f"ОТКАЗ (fail-closed): verify не относится к прогону {run_id}:")
        print(f"  журнал: {recorded}")
        print(f"  verify:  {dict((k, meta[k]) for k in recorded)}")
        print("Дальше: verify тем же планом и солью, что run; либо честный "
              "перезапуск run + verify.")
        return 1
    rl.meta = meta
    rl.mark("verify", "*", "running")
    corpora = build_corpora(load_components(Path(a.components)))
    report = verify(a.src_dsn, a.dst_dsn, plan, Path(a.canaries),
                    corpus_sizes={k: len(v) for k, v in corpora.items()})
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
    print(f"Верификация пройдена. Дальше: python -m sanitizer.cli publish --to <каталог> "
          f"(разрешено={rl.publishable(run_id)})")
    return 0


# START_CONTRACT: cmd_publish
#   PURPOSE: Единственный путь, которым дамп покидает рабочий каталог. Гейт
#            публикации - механизм, а не рекомендация: без verify=done копия
#            не создаётся вовсе (разбор 4, находка 14).
#   INPUTS: { work: рабочий каталог прогона, to: каталог публикации }
#   OUTPUTS: { 0 - опубликовано; 1 - запрещено или уже опубликовано }
#   SIDE_EFFECTS: копирование каталога дампа
# END_CONTRACT: cmd_publish
def cmd_publish(a) -> int:
    import shutil

    work = Path(a.work)
    run_id = _read_run_file(work, "run_id")
    rl = RunLog(work / "runlog.db")
    if not rl.publishable(run_id):
        print(f"ПУБЛИКАЦИЯ ЗАПРЕЩЕНА для run_id={run_id}: журнал прогона не подтверждает,")
        print("что прогон полон (pass1, pass2, verify), все стадии завершены и их")
        print("метаданные согласованы. Записи журнала:")
        for stage, tbl, status, _ in rl.entries(run_id):
            print(f"  {stage:7} {tbl:22} {status}")
        print("Дальше: устраните причину, повторите run и verify.")
        return 1
    dump = _resolve_dump(Path(_read_run_file(work, "dump_path")))
    dst = Path(a.to) / run_id
    if dst.exists():
        print(f"ОТКАЗ: {dst} уже существует - публикация не перезаписывает опубликованное.")
        return 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(dump, dst)
    print(f"опубликовано: {dst}")
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
    p.add_argument("--schema", default="hr")
    p.add_argument("--checkpoint", default="out/plan-state.db")
    p.add_argument("--thread", default="plan")
    p.add_argument("--auto-approve", action="store_true")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("approve")
    p.add_argument("--checkpoint", default="out/plan-state.db")
    p.add_argument("--thread", default="plan")
    p.add_argument("--confirm", nargs="*", default=[])
    p.add_argument("--reject", action="store_true")
    p.set_defaults(fn=cmd_approve)

    p = sub.add_parser("run")
    p.add_argument("--dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    p.add_argument("--plan", default="out/sanitization-plan.yaml")
    p.add_argument("--components", default=DEF_COMPONENTS)
    p.add_argument("--work", default="out")
    p.add_argument("--schema", default="hr")
    p.add_argument("--corpus-cache", default="",
                   help="кэш корпусов от модели; пусто - поставляемые словари")
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
    p.add_argument("--components", default=DEF_COMPONENTS)
    p.add_argument("--report", default="out/verify-report.md")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("publish")
    p.add_argument("--work", default="out")
    p.add_argument("--to", default="out/published")
    p.set_defaults(fn=cmd_publish)

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

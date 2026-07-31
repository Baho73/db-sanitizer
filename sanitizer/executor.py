# START_MODULE_CONTRACT
#   PURPOSE: Проход 1: подготовка артефактов (direct-замены, shuffle-карты),
#            генерация config.yml Greenmask из плана, запуск dump, run_log.
#   SCOPE: Оркеструет; сами замены - в M-MAPPER/cmd_transformer. Источник
#          только читается.
#   DEPENDS: M-POLICY, M-MAPPER, M-RUNLOG
#   LINKS: M-POSTPROC (проход 2 над результатом), V-M-EXECUTOR
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   prepare_artifacts - карты 1:1 (LLM или corpus-fallback), shuffle-карты, отпечаток соли
#   greenmask_config - план -> config.yml (классы только через Cmd)
#   run_pass1 - dump с журналированием
# END_MODULE_MAP
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from sanitizer.mapper import Mapper, Salt, _h, salt_fingerprint
from sanitizer.profiler import ident
from sanitizer.policy import Plan
from sanitizer.runlog import RunLog




# START_CONTRACT: prepare_artifacts
#   PURPOSE: Материализация перед прогоном: direct-замены 1:1 для не-ПДн колонок
#            (LLM либо детерминированный corpus-fallback) и shuffle-перестановки
#            (двухпроходность §5.3: предвычисление в фазе подготовки).
#   INPUTS: { plan, dsn, salt, corpora, out_dir, llm: callable|None }
#   OUTPUTS: { list[Path] - записанные артефакты }
#   SIDE_EFFECTS: чтение источника; запись файлов в out_dir
# END_CONTRACT: prepare_artifacts
def prepare_artifacts(plan: Plan, dsn: str, salt: Salt, corpora: dict[str, list[str]],
                      out_dir: Path, llm=None) -> list[Path]:
    import psycopg
    from psycopg import sql

    out_dir.mkdir(parents=True, exist_ok=True)
    # Проход 1 исполняется в дочернем процессе Greenmask, который читает соль из
    # окружения заново. Ничто не утверждало, что это ТА ЖЕ соль: расхождение дало бы
    # две несогласованные замены одного значения молча. Отпечаток закрывает связь.
    (out_dir / "salt.fingerprint").write_text(salt_fingerprint(salt), encoding="utf-8")
    mapper = Mapper(salt, corpora)
    written: list[Path] = []
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        for qualified, pc in plan.columns.items():
            table, col = qualified.rsplit(".", 1)
            if pc.strategy == "direct":
                cur.execute(sql.SQL("SELECT DISTINCT {c} FROM {t} WHERE {c} IS NOT NULL")
                            .format(c=ident(col), t=ident(table)))
                values = [r[0] for r in cur.fetchall()]
                if llm:
                    mapping = llm(qualified, values)
                else:  # corpus-fallback; полноценный direct - через LLM на гейте.
                    # Замены 1:1 обязаны быть инъективны (энтропия, UNIQUE):
                    # при коллизии базы добавляется детерминированный суффикс.
                    mapping, used = {}, set()
                    for v in sorted(values):
                        base = mapper.pick("org", v.lower(), avoid=v).upper()[:150]
                        fake = base
                        for i in range(1, 998):     # суффикс по модулю 997
                            if fake not in used:
                                break
                            fake = f"{base}-{(_h(salt, 'direct', v) + i) % 997}"
                        if fake in used:            # раньше здесь был вечный цикл
                            raise ValueError(
                                f"{qualified}: корпус исчерпан на значении {v!r}. "
                                f"Дальше: расширьте корпус org либо смените стратегию.")
                        used.add(fake)
                        mapping[v] = fake
                p = out_dir / f"direct.{table}.{col}.json"
                p.write_text(json.dumps(mapping, ensure_ascii=False), encoding="utf-8")
                written.append(p)
        perms = _group_permutations(cur, plan, salt)
        for qualified, pc in plan.columns.items():
            if pc.strategy != "shuffle":
                continue
            table, col = qualified.rsplit(".", 1)
            p = out_dir / f"shuffle.{table}.{col}.json"
            p.write_text(json.dumps(_shuffle_map(cur, plan, table, col, perms),
                                    ensure_ascii=False), encoding="utf-8")
            written.append(p)
    return written


def _single_pk(plan: Plan, table: str) -> str:
    try:
        return plan.pk(table)
    except ValueError as e:
        raise ValueError(f"{e}. Перемешивание требует одноколоночного ключа; "
                         f"дальше: выберите для колонки другую стратегию.") from e


def _entity_column(plan: Plan, table: str, pk: str) -> tuple[str, str]:
    """Ключ сущности таблицы и имя группы перемешивания. Группа - класс
    эквивалентности по FK: employees.id и payroll.employee_id лежат в одном
    классе, значит зарплата и начисления одного человека должны переехать
    к одному и тому же другому человеку."""
    # Приоритет у класса, в который входит ПЕРВИЧНЫЙ ключ таблицы: именно он
    # обозначает саму сущность. Без этого приоритета hr.employees попадала в
    # первый попавшийся класс (position_id) и перемешивалась по должности, а
    # hr.payroll - по сотруднику: группы разные, связь по-прежнему рвалась.
    own = [cls for cls in plan.classes if f"{table}.{pk}" in cls]
    if own:
        return pk, "|".join(sorted(own[0]))
    linked = sorted((sorted(cls), cls) for cls in plan.classes
                    if any(c.rsplit(".", 1)[0] == table for c in cls))
    if linked:
        cls = linked[0][0]
        mine = next(c for c in cls if c.rsplit(".", 1)[0] == table)
        return mine.rsplit(".", 1)[1], "|".join(cls)
    return pk, f"{table}.{pk}"          # таблица ни с кем не связана - сама себе группа


# START_CONTRACT: _group_permutations
#   PURPOSE: Одна перестановка сущностей на группу связанных колонок. Строится по
#            ОБЪЕДИНЕНИЮ значений ключа сущности во всех таблицах группы: у
#            employees 2001 сотрудник, у payroll 2000, и перестановка, собранная
#            по каждому набору отдельно, разъезжается сдвигом на один элемент.
#   INPUTS: { cur: курсор, plan, salt }
#   OUTPUTS: { dict имя группы -> (колонка-сущность по таблице, перестановка) }
#   SIDE_EFFECTS: чтение источника
# END_CONTRACT: _group_permutations
def _group_permutations(cur, plan: Plan, salt: Salt) -> dict:
    from psycopg import sql

    members: dict[str, dict[str, str]] = {}          # группа -> таблица -> колонка-сущность
    for qualified, pc in plan.columns.items():
        if pc.strategy != "shuffle":
            continue
        table = qualified.rsplit(".", 1)[0]
        entity, group = _entity_column(plan, table, _single_pk(plan, table))
        members.setdefault(group, {})[table] = entity

    out: dict[str, dict] = {}
    for group, tables in members.items():
        union: set[str] = set()
        for table, entity in tables.items():
            cur.execute(sql.SQL("SELECT DISTINCT {e}::text FROM {t} WHERE {e} IS NOT NULL")
                        .format(e=ident(entity), t=ident(table)))
            union |= {r[0] for r in cur.fetchall()}
        ids = sorted(union)
        targets = sorted(ids, key=lambda e: _h(salt, "shuffle", group, str(plan.version), e))
        out[group] = {"entity": tables, "perm": dict(zip(ids, targets))}
    return out


def _induced(perm: dict[str, str], present: set[str], e: str) -> str:
    """Перестановка группы, суженная на сущности одной таблицы: идём по циклу,
    пока не попадём в имеющиеся. Сужение перестановки на подмножество остаётся
    перестановкой сущностей. Мультимножество ЗНАЧЕНИЙ сохраняется точно, только
    когда у всех сущностей таблицы одинаковое число строк: иначе донорские строки
    берутся по кругу, часть значений дублируется, часть теряется. Для таблицы
    «одна строка на сущность» и для регулярных начислений условие выполняется."""
    seen = 0
    cur_e = perm.get(e, e)
    while cur_e not in present and seen < len(perm):
        cur_e = perm.get(cur_e, cur_e)
        seen += 1
    return cur_e if cur_e in present else e


# START_CONTRACT: _shuffle_map
#   PURPOSE: Перестановка значений колонки ПО СУЩНОСТИ, а не по строке. Прежний
#            seed зависел от таблицы и колонки, поэтому employees.salary и
#            payroll.amount перемешивались независимо и связь «зарплата - её
#            начисления» рвалась (проверено: корреляция 1.00 -> 0.06).
#   INPUTS: { cur: курсор, plan, table, col, perms: из _group_permutations }
#   OUTPUTS: { dict первичный ключ строки -> новое значение }
#   SIDE_EFFECTS: чтение источника
# END_CONTRACT: _shuffle_map
def _shuffle_map(cur, plan: Plan, table: str, col: str, perms: dict) -> dict[str, str]:
    from psycopg import sql

    pk = _single_pk(plan, table)
    entity, group = _entity_column(plan, table, pk)
    perm = perms[group]["perm"]
    cur.execute(sql.SQL("SELECT {k}::text, {e}::text, {c}::text FROM {t} ORDER BY {e}, {k}")
                .format(k=ident(pk), e=ident(entity), c=ident(col), t=ident(table)))
    by_entity: dict[str, list[tuple[str, str]]] = {}
    for row_pk, ent, value in cur.fetchall():
        by_entity.setdefault(ent, []).append((row_pk, value))

    present = set(by_entity)
    out: dict[str, str] = {}
    for src_ent, rows in by_entity.items():
        donor = by_entity[_induced(perm, present, src_ent)]
        for i, (row_pk, _) in enumerate(rows):
            out[row_pk] = donor[i % len(donor)][1]
    return out






_PASS1_STRATEGIES = {"fake", "generate", "direct", "shuffle", "generalize", "null", "jsonb"}


# START_CONTRACT: greenmask_config
#   PURPOSE: План -> config.yml. Все трансформируемые колонки таблицы - один
#            Cmd-трансформер (правило единого движка §5.1); PK передаётся для
#            shuffle-подстановки и возвращается без изменений.
#   INPUTS: { plan, src_dsn, dump_dir, plan_path, artifacts_dir }
#   OUTPUTS: { dict - структура config.yml }
#   SIDE_EFFECTS: none
# END_CONTRACT: greenmask_config
def greenmask_config(plan: Plan, src_dsn: str, dump_dir: Path, plan_path: Path,
                     artifacts_dir: Path) -> dict:
    tables: dict[str, list[str]] = {}
    for qualified, pc in plan.columns.items():
        if pc.strategy in _PASS1_STRATEGIES:
            table, col = qualified.rsplit(".", 1)
            tables.setdefault(table, []).append(col)

    transformations = []
    for table, cols in sorted(tables.items()):
        schema, name = table.split(".")
        # Первичный ключ берётся из плана, а не угадывается по имени «id»:
        # он нужен трансформеру для подстановки предвычисленной перестановки.
        pk = plan.pk(table)
        columns = [{"name": pk, "not_affected": True}] if pk not in cols else []
        columns += [{"name": c} for c in sorted(cols)]
        transformations.append({
            "schema": schema, "name": name,
            "transformers": [{
                "name": "Cmd",
                "params": {
                    "executable": "python",
                    "args": ["-m", "sanitizer.cmd_transformer",
                             "--plan", str(plan_path), "--table", table,
                             "--pk", pk, "--artifacts", str(artifacts_dir)],
                    "driver": {"name": "json"},
                    "timeout": "600s",
                    "expected_exit_code": 0,
                    "columns": columns,
                },
            }],
        })
    import os
    # схема берётся из плана: дамп «только hr» молча терял бы всё остальное
    schemas = sorted({q.split(".", 1)[0] for q in plan.columns})
    if len(schemas) != 1:
        raise ValueError(f"план охватывает несколько схем {schemas}; дамп делается по одной")
    return {
        "common": {"pg_bin_path": os.environ.get("PG_BIN_PATH", "/usr/bin"), "tmp_dir": "/tmp"},
        "storage": {"type": "directory", "directory": {"path": str(dump_dir)}},
        "dump": {"pg_dump_options": {"dbname": src_dsn, "schema": schemas[0]},
                 "transformation": transformations},
    }







def run_pass1(plan: Plan, src_dsn: str, salt: Salt, corpora: dict, work_dir: Path,
              runlog: RunLog, run_id: str, greenmask_bin: str = "greenmask",
              plan_path: Path | None = None) -> Path:
    """Артефакты -> конфиг -> greenmask dump. Возвращает каталог дампа.
    Падение = failed в run_log; перезапуск прохода 1 целиком (§5.7)."""
    artifacts = work_dir / "artifacts"
    dump_dir = work_dir / "dump"
    dump_dir.mkdir(parents=True, exist_ok=True)
    runlog.mark("pass1", "*", "running")
    try:
        prepare_artifacts(plan, src_dsn, salt, corpora, artifacts)
        cfg = greenmask_config(plan, src_dsn, dump_dir, plan_path or work_dir / "plan.yaml", artifacts)
        cfg_path = work_dir / "greenmask.yml"
        cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        # Соль передаётся дочернему процессу ЯВНО, а не подхватывается из
        # окружения: единственный источник истины - объект Salt родителя.
        # Отпечаток в артефактах остаётся вторым рубежом (ручной запуск Cmd).
        import os
        env = {**os.environ,
               "MASTER_SALT": salt.master.decode(),
               "RECIPIENT": salt.recipient,
               "GENERATION": salt.generation,
               "MASTER_SALT_VERSION": str(salt.version)}
        subprocess.run([greenmask_bin, "--config", str(cfg_path), "dump"],
                       check=True, capture_output=True, text=True, env=env)
        # greenmask пишет каждый дамп в подкаталог-метку времени
        latest = max((p for p in dump_dir.iterdir() if p.is_dir() and p.name.isdigit()),
                     key=lambda p: int(p.name))
        runlog.mark("pass1", "*", "done")
        return latest
    except Exception:
        runlog.mark("pass1", "*", "failed")
        raise




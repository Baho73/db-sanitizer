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
#   salt_fingerprint - необратимый отпечаток производной соли для сверки проходов
#   prepare_artifacts - direct-карты (LLM или corpus-fallback) + shuffle-карты
#   greenmask_config - план -> config.yml (классы только через Cmd)
#   run_pass1 - dump с журналированием
# END_MODULE_MAP
from __future__ import annotations

import json
import random
import subprocess
from pathlib import Path

import yaml

from sanitizer.mapper import Mapper, Salt, _h, salt_fingerprint
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
                cur.execute(f"SELECT DISTINCT {col} FROM {table} WHERE {col} IS NOT NULL")
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
                        i = 0
                        while fake in used:
                            i += 1
                            fake = f"{base}-{(_h(salt, 'direct', v) + i) % 997}"
                        used.add(fake)
                        mapping[v] = fake
                p = out_dir / f"direct.{table}.{col}.json"
                p.write_text(json.dumps(mapping, ensure_ascii=False), encoding="utf-8")
                written.append(p)
            elif pc.strategy == "shuffle":
                cur.execute(f"SELECT id::text, {col}::text FROM {table} ORDER BY id")
                rows = cur.fetchall()
                values = [v for _, v in rows]
                seed = _h(salt, "shuffle", table, col, str(plan.version))
                random.Random(seed).shuffle(values)  # детерминированный seed (§5.3)
                p = out_dir / f"shuffle.{table}.{col}.json"
                p.write_text(json.dumps(dict(zip((pk for pk, _ in rows), values)),
                                        ensure_ascii=False), encoding="utf-8")
                written.append(p)
    return written






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
        columns = [{"name": "id", "not_affected": True}] if "id" not in cols else []
        columns += [{"name": c} for c in sorted(cols)]
        transformations.append({
            "schema": schema, "name": name,
            "transformers": [{
                "name": "Cmd",
                "params": {
                    "executable": "python",
                    "args": ["-m", "sanitizer.cmd_transformer",
                             "--plan", str(plan_path), "--table", table,
                             "--artifacts", str(artifacts_dir)],
                    "driver": {"name": "json"},
                    "timeout": "600s",
                    "expected_exit_code": 0,
                    "columns": columns,
                },
            }],
        })
    import os
    return {
        "common": {"pg_bin_path": os.environ.get("PG_BIN_PATH", "/usr/bin"), "tmp_dir": "/tmp"},
        "storage": {"type": "directory", "directory": {"path": str(dump_dir)}},
        "dump": {"pg_dump_options": {"dbname": src_dsn, "schema": "hr"},
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
        subprocess.run([greenmask_bin, "--config", str(cfg_path), "dump"],
                       check=True, capture_output=True, text=True)
        # greenmask пишет каждый дамп в подкаталог-метку времени
        latest = max((p for p in dump_dir.iterdir() if p.is_dir() and p.name.isdigit()),
                     key=lambda p: int(p.name))
        runlog.mark("pass1", "*", "done")
        return latest
    except Exception:
        runlog.mark("pass1", "*", "failed")
        raise




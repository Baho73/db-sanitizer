# START_MODULE_CONTRACT
#   PURPOSE: Журнал прогонов (§5.7): стадии, таблицы, статусы, версии всех
#            артефактов. Правило публикации: дамп не публикуется, пока
#            верификация не завершена и все записи done.
#   SCOPE: SQLite-файл в контуре; наружу не уходит. Не знает о содержимом данных.
#   DEPENDS: none (stdlib)
#   LINKS: M-EXECUTOR, M-POSTPROC, M-VERIFIER, V-M-RUNLOG
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   RunLog - open/start_run/mark/publishable/entries
# END_MODULE_MAP
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_log (
  run_id TEXT, plan_version TEXT, master_salt_version INTEGER,
  salt_generation TEXT, recipient_id TEXT, corpus_version TEXT,
  cache_version TEXT, tool_version TEXT,
  stage TEXT CHECK (stage IN ('pass1','pass2','verify')),
  tbl TEXT, status TEXT CHECK (status IN ('running','done','failed')),
  checksum TEXT, ts REAL
)"""


class RunLog:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute(_SCHEMA)
        self.meta: dict = {}

    def start_run(self, plan_version: str, recipient: str, generation: str,
                  master_salt_version: int = 1, corpus_version: str = "fixtures-1",
                  cache_version: str = "none", tool_version: str = "0.1.0") -> str:
        run_id = uuid.uuid4().hex[:12]
        self.meta = {"run_id": run_id, "plan_version": plan_version,
                     "master_salt_version": master_salt_version,
                     "salt_generation": generation, "recipient_id": recipient,
                     "corpus_version": corpus_version, "cache_version": cache_version,
                     "tool_version": tool_version}
        return run_id

    def mark(self, stage: str, table: str, status: str, checksum: str = ""):
        self.db.execute(
            "INSERT INTO run_log VALUES (:run_id,:plan_version,:master_salt_version,"
            ":salt_generation,:recipient_id,:corpus_version,:cache_version,:tool_version,"
            ":stage,:tbl,:status,:checksum,:ts)",
            {**self.meta, "stage": stage, "tbl": table, "status": status,
             "checksum": checksum, "ts": time.time()})
        self.db.commit()

    # START_CONTRACT: publishable
    #   PURPOSE: Гейт публикации (§5.7): все стадии run завершены и без failed.
    #   INPUTS: { run_id: str }
    #   OUTPUTS: { bool }
    #   SIDE_EFFECTS: none
    # END_CONTRACT: publishable
    def publishable(self, run_id: str) -> bool:
        # порядок по rowid, не по ts: часы контейнеров и буферизация bind-mount
        # не влияют на порядок вставки
        rows = self.db.execute(
            "SELECT stage, tbl, status FROM run_log WHERE run_id=? "
            "AND rowid = (SELECT MAX(rowid) FROM run_log r2 WHERE r2.run_id=run_log.run_id "
            "             AND r2.stage=run_log.stage AND r2.tbl=run_log.tbl)", (run_id,)).fetchall()
        if not rows or any(s != "done" for *_, s in rows):
            return False
        return "verify" in {stage for stage, *_ in rows}

    def entries(self, run_id: str) -> list[tuple]:
        return self.db.execute("SELECT stage, tbl, status, checksum FROM run_log "
                               "WHERE run_id=? ORDER BY ts", (run_id,)).fetchall()

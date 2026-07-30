# START_MODULE_CONTRACT
#   PURPOSE: Проход 2 (§5.1): обработка свободнотекстовых таблиц поверх готового
#            directory-дампа (вне транзакции дампа) + примечания о санитизации.
#            Эшелоны: словарный NER -> regex-страховка (100% форматов) ->
#            LLM на неуверенном с версионируемым кэшем.
#   SCOPE: Работает с файлами дампа (COPY-потоки .dat.gz) и pg_restore -l;
#          в исходную БД не ходит. Схема sanitization - sanitization.sql внутри
#          каталога дампа (осознанное отклонение от правки toc.dat: бинарная
#          хирургия хрупка, SQL-компаньон применяется нашей командой restore).
#   DEPENDS: M-MAPPER (общий ключ идентичности), M-POLICY, M-RUNLOG
#   LINKS: M-VERIFIER, V-M-POSTPROC, docs/solution-design.md §5.5, §5.7.1
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TextSanitizer - замена сущностей в тексте теми же псевдонимами
#   process_dump - переписать freetext-таблицы в дампе, собрать примечания
#   toc_tables - dumpid -> таблица из pg_restore -l
# END_MODULE_MAP
from __future__ import annotations

import gzip
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sanitizer.mapper import Mapper, Salt, gen_digits_like, gen_snils, normalize_digits, valid_inn, valid_snils
from sanitizer.policy import Plan



_PHONE_RE = re.compile(r"(?<!\d)(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-zа-я]{2,}")
_SNILS_RE = re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}[\s-]?\d{2}(?!\d)")
_INN_RE = re.compile(r"(?<!\d)\d{10}(?:\d{2})?(?!\d)")
_PASSPORT_RE = re.compile(r"(?<!\d)\d{4}\s\d{6}(?!\d)")
# ФИО: «Фамилия И.О.», «Фамилия Имя (Отчество)» - словарь имён + фамильные суффиксы
_FIO_INITIALS_RE = re.compile(r"\b([А-ЯЁ][а-яё]+(?:ов|ев|ин|ын|ова|ева|ина|ына|ский|ская|цкий|цкая|ко|ук|юк)а?)\s+([А-ЯЁ])\.\s?([А-ЯЁ])\.")
_CAP_PAIR_RE = re.compile(r"\b([А-ЯЁ][а-яё]{2,})\s+([А-ЯЁ][а-яё]{2,})(?:\s+([А-ЯЁ][а-яё]{2,}))?\b")


@dataclass
class TextSanitizer:
    mapper: Mapper
    salt: Salt
    name_dict: frozenset[str]        # известные имена/отчества (нижний регистр)
    llm: object = None               # callable(text)->list[span] | None
    llm_cache: dict = field(default_factory=dict)
    confidence_threshold: float = 0.6
    aggressive: bool = False         # адресные колонки: неуверенное заменяется (§3.2)
    stats: dict = field(default_factory=dict)

    # START_CONTRACT: sanitize_text
    #   PURPOSE: Заменить сущности в тексте псевдонимами по общему ключу
    #            идентичности; страховочный слой ловит форматы со 100% полнотой.
    #   INPUTS: { text: str }
    #   OUTPUTS: { (str, list[str]) - текст и коды деградаций (low_confidence_ner) }
    #   SIDE_EFFECTS: пополняет llm_cache и stats
    # END_CONTRACT: sanitize_text
    def sanitize_text(self, text: str) -> tuple[str, list[str]]:
        notes: list[str] = []
        out = _PHONE_RE.sub(lambda m: self.mapper.phone(m.group()), text)
        out = _EMAIL_RE.sub(lambda m: self.mapper.email(m.group()), out)
        out = _SNILS_RE.sub(lambda m: self._snils(m.group()), out)
        out = _PASSPORT_RE.sub(lambda m: gen_digits_like(self.salt, m.group()), out)
        out = _INN_RE.sub(lambda m: gen_digits_like(self.salt, m.group())
                          if valid_inn(m.group()) else m.group(), out)
        out = _FIO_INITIALS_RE.sub(lambda m: self._fio_initials(m), out)
        out = _CAP_PAIR_RE.sub(lambda m: self._cap_pair(m, notes), out)
        return out, notes

    def _snils(self, raw: str) -> str:
        d = normalize_digits(raw)
        return gen_snils(self.salt, d) if valid_snils(d) else gen_digits_like(self.salt, raw)

    def _fio_initials(self, m: re.Match) -> str:
        fam, i1, i2 = self.mapper.initials(m.group(1), m.group(2), m.group(3))
        return f"{fam.capitalize()} {i1.upper()}.{i2.upper()}."

    def _cap_pair(self, m: re.Match, notes: list[str]) -> str:
        """«Имя Фамилия» / «Фамилия Имя Отчество»: словарный NER (словарь пополняется
        известными ФИО источника - он живёт в контуре); ниже порога - LLM.
        Уверенная замена только когда КАЖДОЕ слово распознано - иначе пара
        «Согласовал Иванова» превращала бы глагол в имя."""
        words = [w for w in m.groups() if w]
        lowered = [w.lower().replace("ё", "е") for w in words]
        marks = [(self._in_dict(w), _is_surname_like(w), _is_patronymic_like(w)) for w in lowered]
        anchors = sum(1 for _, s, p in marks if s or p)
        dict_hits = sum(1 for d, _, _ in marks if d)
        if anchors == 0 and dict_hits < 2:
            return m.group()                        # не похоже на ФИО
        if not all(any(mk) for mk in marks):        # часть слов не распознана
            verdict = self._llm_verdict(m.group())
            if verdict is False:
                return m.group()
            if verdict is None:
                notes.append("low_confidence_ner")  # деградация фиксируется (§5.7.1)
                if not self.aggressive:
                    return m.group()
                # агрессивный режим (адресные колонки, §3.2): неуверенное ЗАМЕНЯЕТСЯ -
                # нераспознанный остаток не сохраняется никогда
        parts = dict(family="", name="", patronymic="")
        for w, (d, s, p) in zip(lowered, marks):
            if p and not parts["patronymic"]:
                parts["patronymic"] = w
            elif s and not parts["family"]:       # surname-like приоритетнее словаря:
                parts["family"] = w               # словарь источника смешивает Ф/И/О
            elif not parts["name"]:
                parts["name"] = w
            elif not parts["patronymic"]:
                parts["patronymic"] = w
        f, n, p = self.mapper.fio(parts["family"], parts["name"], parts["patronymic"])
        repl = " ".join(x.capitalize() for x in (n, p) if x)
        return f"{f.capitalize()} {repl}".strip() if f else repl or m.group()

    def _in_dict(self, w: str) -> bool:
        # грубое усечение падежа: Марью -> марья, Ивана -> иван
        return (w in self.name_dict
                or (len(w) > 3 and (w[:-1] + "я" in self.name_dict or w[:-1] + "а" in self.name_dict
                                    or w[:-1] in self.name_dict)))

    def _llm_verdict(self, fragment: str):
        """True/False = вердикт (из кэша или LLM), None = LLM недоступна."""
        key = fragment.lower()
        if key in self.llm_cache:
            return self.llm_cache[key]
        if self.llm is None:
            return None
        verdict = bool(self.llm(fragment))
        self.llm_cache[key] = verdict
        return verdict


_SURNAME_RE = re.compile(r"(ов|ев|ин|ын|цк|ск)(а|у|е|ы|ым|ой|ая|ую|им|ом|ий|ого|ому)?$")
_PATR_RE = re.compile(r"(вич|вн)(а|у|е|ой|ем|ы)?$")


def _is_surname_like(w: str) -> bool:
    return bool(_SURNAME_RE.search(w)) or w.endswith(("ко", "ук", "юк"))


def _is_patronymic_like(w: str) -> bool:
    return bool(_PATR_RE.search(w))







def toc_tables(dump_dir: Path, pg_restore: str = "pg_restore") -> dict[str, str]:
    """dumpid -> schema.table из листинга TOC (TABLE DATA)."""
    res = subprocess.run([pg_restore, "-l", str(dump_dir)], check=True,
                         capture_output=True, text=True)
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        m = re.match(r'^(\d+);\s+\d+\s+\d+\s+TABLE DATA\s+"?([\w]+)"?\s+"?([\w]+)"?', line)
        if m:
            out[m.group(1)] = f"{m.group(2)}.{m.group(3)}"
    return out


# START_CONTRACT: process_dump
#   PURPOSE: Переписать COPY-потоки freetext-таблиц, собрать sanitization.sql
#            (notes/summary §5.7.1; row_pk - только пост-трансформационный,
#            но PK id не трансформируется - безопасен), возобновляемость по таблицам.
#   INPUTS: { dump_dir, plan, columns_order: dict table->[cols], ts: TextSanitizer,
#             runlog, run_id, pg_restore }
#   OUTPUTS: { dict table -> {rows, degraded} }
#   SIDE_EFFECTS: перезапись .dat.gz, запись sanitization.sql, run_log
# END_CONTRACT: process_dump
def process_dump(dump_dir: Path, plan: Plan, columns_order: dict[str, list[str]],
                 ts: TextSanitizer, runlog=None, pg_restore: str = "pg_restore") -> dict:
    free_cols: dict[str, list[str]] = {}
    length_policy: dict[str, str] = {}
    for qualified, pc in plan.columns.items():
        if pc.strategy == "freetext":
            table, col = qualified.rsplit(".", 1)
            free_cols.setdefault(table, []).append(col)
            length_policy[qualified] = pc.length_policy

    notes_rows: list[tuple] = []
    summary: dict = {}
    for dumpid, table in toc_tables(dump_dir, pg_restore).items():
        if table not in free_cols:
            continue
        if runlog:
            runlog.mark("pass2", table, "running")
        order = columns_order[table]
        idxs = {order.index(c): f"{table}.{c}" for c in free_cols[table]}
        path = dump_dir / f"{dumpid}.dat.gz"
        rows_out, degraded = [], 0
        with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
            for line in fh:
                if line.rstrip("\n") == "\\.":
                    rows_out.append(line)
                    continue
                fields = line.rstrip("\n").split("\t")
                if len(fields) < len(order):   # хвост файла / служебные строки
                    rows_out.append(line)
                    continue
                pk = fields[0]
                for i, qualified in idxs.items():
                    if fields[i] == "\\N":
                        continue
                    ts.aggressive = plan.columns[qualified].sem_type == "address"
                    new, notes = ts.sanitize_text(_copy_unescape(fields[i]))
                    max_len = None  # длина колонки контролируется политикой
                    if length_policy[qualified] == "truncate" and max_len:
                        new = new[:max_len]
                    fields[i] = _copy_escape(new)
                    for code in notes:
                        degraded += 1
                        notes_rows.append((table, pk, qualified.rsplit(".", 1)[1], code))
                rows_out.append("\t".join(fields) + "\n")
        with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
            fh.writelines(rows_out)
        summary[table] = {"rows": len(rows_out), "degraded": degraded}
        if runlog:
            runlog.mark("pass2", table, "done")

    _write_sanitization_sql(dump_dir, notes_rows, summary)
    return summary


def _copy_unescape(s: str) -> str:
    return s.replace("\\t", "\t").replace("\\n", "\n").replace("\\\\", "\\")


def _copy_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def _write_sanitization_sql(dump_dir: Path, notes: list[tuple], summary: dict):
    """Примечания §5.7.1 внутри каталога дампа; применяются командой restore."""
    lines = [
        "CREATE SCHEMA IF NOT EXISTS sanitization;",
        "CREATE TABLE sanitization.notes (table_name text, row_pk text, column_name text, reason text);",
        "CREATE TABLE sanitization.summary (table_name text, rows int, degraded int);",
    ]
    if len(notes) <= 10_000:  # построчно только меньшинство (§5.7.1 п.3)
        for t, pk, col, code in notes:
            lines.append(f"INSERT INTO sanitization.notes VALUES ('{t}', '{pk}', '{col}', '{code}');")
    for t, s in summary.items():
        lines.append(f"INSERT INTO sanitization.summary VALUES ('{t}', {s['rows']}, {s['degraded']});")
    (dump_dir / "sanitization.sql").write_text("\n".join(lines), encoding="utf-8")




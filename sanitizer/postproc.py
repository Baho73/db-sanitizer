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

from sanitizer.mapper import (
    Mapper, Salt, gen_digits_like, gen_inn10, gen_inn12, gen_luhn_like, gen_ogrn,
    gen_snils, luhn_ok, normalize_digits, valid_inn, valid_ogrn, valid_snils,
)
from sanitizer.policy import Plan



_PHONE_RE = re.compile(r"(?<!\d)(?:\+7|8|7)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)")
# домены бывают кириллическими: ivan@домен.рф
_EMAIL_RE = re.compile(r"[A-Za-zА-Яа-яЁё0-9._%+-]+@[A-Za-zА-Яа-яЁё0-9.-]+\.[A-Za-zА-Яа-яЁё]{2,}")
# Идентификатор в тексте опознаётся КОНТРОЛЬНОЙ СУММОЙ, а не пунктуацией:
# один токен ловит и «09085653089», и «123-456-789 64», и «123 456 789 64».
# Разделители допускаются одиночные - иначе «заявка 12345 от 20 05 2026»
# склеилась бы в одно число.
_ID_TOKEN_RE = re.compile(r"(?<![+\d])\d(?:[\s-]?\d){9,18}(?!\d)")
# Паспорт РФ (4+6 цифр). Контрольной суммы у него нет - слой обязан покрывать
# написания ФОРМАТОМ (ревью-2, Н3): пробел(ы), дефис и «серия 4501[,] номер
# 123456». Голые 10 цифр подряд сознательно НЕ матчатся - это конфликт с
# ИНН-10, и там решает контрольная сумма (_checksummed).
_PASSPORT_RE = re.compile(
    r"(?<!\d)(?:[Сс]ерия\s+)?\d{4}(?:[\s-]+,?\s*|,\s*)(?:[Нн]омер\s+)?\d{6}(?!\d)")
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
    def sanitize_text(self, text: str, aggressive: bool | None = None) -> tuple[str, list[str]]:
        # Адресная колонка: значение заменяется ЦЕЛИКОМ синтетическим адресом.
        # Патчить сущности внутри нельзя - нераспознанный остаток (посёлок, улица,
        # дом, квартира, код домофона) сохранился бы в копии, а §3.2 это запрещает.
        # Режим приходит аргументом, а не через мутацию поля в цикле: от порядка
        # обхода колонок поведение зависеть не должно.
        if aggressive is None:
            aggressive = self.aggressive
        if aggressive:
            return self.synthetic_address(text), []
        notes: list[str] = []

        # ОДИН проход. Совпадения ищутся по ИСХОДНОМУ тексту, замены
        # накладываются в конце, и заменённый участок повторно не рассматривается.
        # Последовательные .sub() по уже изменённой строке давали двойную
        # трансформацию: «123-456-789 64» заменялся в плоский СНИЛС, который
        # тут же попадал под шаблон идентификатора и заменялся ВТОРОЙ раз -
        # одно значение получало разные замены в двух написаниях, и сквозная
        # консистентность §3.2 ломалась молча.
        # Порядок: сначала то, что решается доказательством (контрольная сумма),
        # потом форматные эвристики.
        claimed: list[tuple[int, int, str]] = []

        def vacant(start: int, end: int) -> bool:
            return all(end <= s or start >= e for s, e, _ in claimed)

        # Порядок: от БОЛЕЕ КОНТЕКСТНОГО к менее. Телефон и паспорт опознаются по
        # якорю («+7», «8», формат 4+6), то есть несут больше свидетельств, чем
        # голая цифровая последовательность. Обратный порядок ломался так:
        # у «+7 916 123-45-67» внутренние 10 цифр проходят контрольную сумму ИНН,
        # распознаватель идентификаторов забирал участок первым, и телефон уезжал
        # через gen_inn10 - расходясь с заменой того же номера в колонке.
        # Случай «номер с якорем телефона, но целиком валидный идентификатор»
        # разбирается внутри _phone: контрольная сумма ВСЕЙ строки сильнее якоря.
        for pattern, handler in (
            (_EMAIL_RE, lambda m: self.mapper.email(m.group())),
            (_PHONE_RE, self._phone),
            (_PASSPORT_RE, self._passport),
            (_ID_TOKEN_RE, self._checksummed),
            (_FIO_INITIALS_RE, self._fio_initials),
            (_CAP_PAIR_RE, lambda m: self._cap_pair(m, notes, aggressive)),
        ):
            for m in pattern.finditer(text):
                if not vacant(*m.span()):
                    continue
                replacement = handler(m)
                if replacement is None or replacement == m.group():
                    continue
                claimed.append((m.start(), m.end(), replacement))

        if not claimed:
            return text, notes
        claimed.sort()
        out, cursor = [], 0
        for start, end, replacement in claimed:
            out.append(text[cursor:start])
            out.append(replacement)
            cursor = end
        out.append(text[cursor:])
        return "".join(out), notes

    # START_CONTRACT: synthetic_address
    #   PURPOSE: Полная замена адресной строки. Делегирует Mapper: генератор
    #            обязан быть один на оба прохода, иначе один адрес в колонке и в
    #            тексте получает две разные замены.
    #   INPUTS: { raw: str - исходная строка любой грязности }
    #   OUTPUTS: { str - «Регион, г. Город, ул. Улица, д. N, кв. M» }
    #   SIDE_EFFECTS: none
    # END_CONTRACT: synthetic_address
    def synthetic_address(self, raw: str) -> str:
        return self.mapper.synthetic_address(raw)

    # START_CONTRACT: _checksummed
    #   PURPOSE: Цифровая последовательность -> замена, если её контрольная сумма
    #            опознаёт ИНН, СНИЛС или ОГРН. Число без валидной КС не трогается:
    #            номер заявки и год выпуска станка персональными данными не являются.
    #   INPUTS: { raw: str - последовательность из 10-15 цифр }
    #   OUTPUTS: { str - замена или исходник }
    #   SIDE_EFFECTS: none
    # END_CONTRACT: _checksummed
    def _phone(self, m: re.Match) -> str:
        """Телефон. Разметка формы («+», скобки, дефисы) побеждает контрольную
        сумму: СТРУКТУРНАЯ колонка про суммы не знает и всегда идёт через
        mapper.phone, а расхождение колонки и текста - нарушение §3.2.
        У ГОЛОЙ последовательности цифр разметки нет, и единственное доступное
        свидетельство - контрольная сумма; там она и решает."""
        raw = m.group()
        if raw.strip(" 0123456789"):          # есть «+», скобка или дефис
            return self.mapper.phone(raw)
        # Только цифры и пробелы: классификация по ГРУППИРОВКЕ, а не по
        # сплющенным цифрам (ревью-2, minor). «8 950 420 61 18» - группировка
        # телефона X XXX XXX XX XX, и ~1% таких строк проходил контрольную
        # сумму СНИЛС и уезжал через gen_snils - расходясь со структурной
        # колонкой, которая всегда идёт через mapper.phone. Прежний strip()
        # это различие стирал.
        if [len(g) for g in raw.split()] == [1, 3, 3, 2, 2]:
            return self.mapper.phone(raw)
        by_checksum = self._checksummed(m)
        return by_checksum if by_checksum is not None else self.mapper.phone(raw)

    def _passport(self, m: re.Match) -> str:
        """Ключ идентичности - 10 цифр series‖number через ОДНУ FPE-10
        (ревью-2, Н3): структурная пара passport_series+passport_number
        трансформируется тем же ключом, и текст обязан с ней совпасть.
        Разделители исходника сохраняются (_reshape): «4509-123456» ->
        «4812-654321», «серия 4501, номер 123456» -> «серия 4812, номер 654321»."""
        fake = gen_digits_like(self.salt, normalize_digits(m.group()))
        return _reshape(m.group(), fake)

    def _checksummed(self, m: re.Match) -> str | None:
        raw = m.group()
        d = normalize_digits(raw)
        if valid_snils(d):
            fake = gen_snils(self.salt, d)
        elif valid_inn(d):
            fake = gen_inn12(self.salt, d) if len(d) > 10 else gen_inn10(self.salt, d)
        elif valid_ogrn(d):
            fake = gen_ogrn(self.salt, d, ip=len(d) == 15)
        elif luhn_ok(d):
            fake = gen_luhn_like(self.salt, d)      # номер карты
        else:
            return None                              # номер заявки, год, инвентарный
        # Разделители исходника сохраняются: «123-456-789 64» -> «381-116-374 30».
        # Заодно это делает замену непохожей на новый плоский идентификатор.
        return _reshape(raw, fake)

    def _fio_initials(self, m: re.Match) -> str:
        fam, i1, i2 = self.mapper.initials(m.group(1), m.group(2), m.group(3))
        return f"{fam.capitalize()} {i1.upper()}.{i2.upper()}."

    def _cap_pair(self, m: re.Match, notes: list[str], aggressive: bool = False) -> str:
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
                if not aggressive:
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
        verdict = self.llm(fragment)
        if verdict is None:
            return None          # модель не ответила внятно - это «не знаю»,
                                 # а не «не персональные данные»; в кэш не кладём
        verdict = bool(verdict)
        self.llm_cache[key] = verdict
        return verdict


def _reshape(src: str, digits: str) -> str:
    """Цифры замены раскладываются по позициям цифр исходника; разделители целы."""
    it = iter(digits)
    return "".join(next(it, "0") if ch.isdigit() else ch for ch in src)


_SURNAME_RE = re.compile(r"(ов|ев|ин|ын|цк|ск)(а|у|е|ы|ым|ой|ая|ую|им|ом|ий|ого|ому)?$")
_PATR_RE = re.compile(r"(вич|вн)(а|у|е|ой|ем|ы)?$")


def _is_surname_like(w: str) -> bool:
    return bool(_SURNAME_RE.search(w)) or w.endswith(("ко", "ук", "юк"))


def _is_patronymic_like(w: str) -> bool:
    return bool(_PATR_RE.search(w))







# Квотированный идентификатор в листинге pg_restore -l: кавычки внутри
# раздвоены (тот же fmtId, что ident(), только в обратную сторону).
_TOC_IDENT = r'(?:"((?:[^"]|"")+)"|([A-Za-z0-9_]+))'
_TOC_DATA_RE = re.compile(
    rf"^(\d+);\s+\d+\s+\d+\s+TABLE DATA\s+{_TOC_IDENT}\s+{_TOC_IDENT}(?:\s|$)")
_TOC_DATA_LINE_RE = re.compile(r"^\d+;\s+\d+\s+\d+\s+TABLE DATA\s")


def _toc_ident(quoted: str | None, plain: str | None) -> str:
    return quoted.replace('""', '"') if quoted is not None else plain


def toc_tables(dump_dir: Path, pg_restore: str = "pg_restore") -> dict[str, str]:
    """dumpid -> schema.table из листинга TOC (TABLE DATA)."""
    res = subprocess.run([pg_restore, "-l", str(dump_dir)], check=True,
                         capture_output=True, text=True)
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if not _TOC_DATA_LINE_RE.match(line):
            continue
        m = _TOC_DATA_RE.match(line)
        if m is None:
            # Fail-closed (ревью-2, Н2): молчаливый пропуск строки здесь
            # означал, что таблица с квотированным именем («Odd Schema».
            # «User Table») уезжала в дамп несанитизированной - регэксп
            # «"?([\w]+)"?» сворачивал её в «Odd.Schema», и free_cols её
            # не находил.
            raise ValueError(f"toc_tables: не разобрана строка TABLE DATA: {line!r}")
        out[m.group(1)] = f"{_toc_ident(m.group(2), m.group(3))}." \
                          f"{_toc_ident(m.group(4), m.group(5))}"
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
                 ts: TextSanitizer, runlog=None, pg_restore: str = "pg_restore",
                 max_len: dict[str, int | None] | None = None,
                 resume: bool = True) -> dict:
    free_cols: dict[str, list[str]] = {}
    length_policy: dict[str, str] = {}
    for qualified, pc in plan.columns.items():
        if pc.strategy == "freetext":
            table, col = qualified.rsplit(".", 1)
            free_cols.setdefault(table, []).append(col)
            length_policy[qualified] = pc.length_policy

    limits = max_len or {}
    # Накопленное состояние прохода 2 живёт рядом с дампом. Без него возобновление
    # обнуляло отчёт: пропущенная таблица получала {rows:0, degraded:0}, а
    # sanitization.sql перезаписывался целиком - и проверка деградаций, ради
    # которой всё делалось, после возобновления гарантированно молчала.
    state_path = dump_dir / "sanitization-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))         if (resume and state_path.exists()) else {"notes": [], "summary": {}}
    notes_rows: list[tuple] = [tuple(n) for n in state["notes"]]
    summary: dict = dict(state["summary"])
    files: dict = dict(state.get("files", {}))
    # Возобновляемость (§5.7) была объявлена и не реализована: журнал писался, но
    # не читался, и повторный вызов обрабатывал таблицу ВТОРОЙ раз - фейковый
    # телефон снова попадал под шаблон и заменялся на другой фейк.
    already_done = _completed_tables(runlog) if resume else set()
    toc = toc_tables(dump_dir, pg_restore)
    # Сверка покрытия (ревью-2, Н2): freetext-таблица плана вне TOC раньше
    # означала молчаливый пропуск - свободный текст уезжал в дамп как есть,
    # без ошибки и без отметки degraded. Отказ с перечислением закрывает
    # весь класс «таблица плана потерялась в дампе».
    missing = sorted(set(free_cols) - set(toc.values()))
    if missing:
        raise ValueError("freetext-таблицы плана не найдены в TOC дампа: "
                         + ", ".join(missing))
    for dumpid, table in toc.items():
        if table not in free_cols:
            continue
        path = dump_dir / f"{dumpid}.dat.gz"
        rec = files.get(table) if resume else None
        if rec:
            # Защита окна краха (ревью-2, Н1): замена файла неатомарна
            # относительно записи state, поэтому решение о пропуске принимает
            # не пара «журнал+summary» (они расходятся при обрыве), а хэш
            # самого файла против записанных до/после.
            digest = _sha256(path)
            if digest == rec.get("post"):
                continue          # таблица завершена прошлой попыткой
            if digest != rec.get("pre"):
                # Крах между tmp.replace и записью post-хэша: файл не совпадает
                # ни с исходным, ни с завершённым состоянием. Молчаливая
                # повторная обработка дала бы двойную трансформацию (телефон
                # уезжал в третье значение) - отказ, а не «авось».
                raise ValueError(
                    f"{table}: файл дампа не совпадает ни с исходным, ни с "
                    f"завершённым состоянием прошлого прогона (крах посреди "
                    f"замены). Дальше: перезапустите прогон из свежего дампа "
                    f"прохода 1 - повторная обработка запрещена, она дала бы "
                    f"двойную трансформацию.")
            # digest == pre: замена не состоялась, обрабатываем заново - безопасно
        elif table in already_done and table in summary:
            continue          # итоги прошлой попытки уже в накопленном состоянии
        if runlog:
            runlog.mark("pass2", table, "running")
        order = columns_order[table]
        idxs = {order.index(c): f"{table}.{c}" for c in free_cols[table]}
        # ключ строки для примечаний берётся из плана, а не как первая колонка
        # файла: первой может стоять что угодно, вплоть до персональных данных
        # Составной или отсутствующий ключ - отказ, а не «первая колонка».
        # row_pk уезжает наружу внутри sanitization.notes: подставить туда
        # первую попавшуюся колонку значит опубликовать её значение.
        pk_idx = order.index(plan.pk(table))
        tmp = path.with_name(path.name + ".tmp")
        rows, degraded = 0, 0
        # pre-хэш персистируется ДО замены файла: иначе крах между replace и
        # записью state выглядел бы при возобновлении как «таблица не
        # обрабатывалась» - и получал бы вторую трансформацию.
        files[table] = {"pre": _sha256(path)}
        _write_state(state_path, notes_rows, summary, files)
        # Поток вместо списка строк в памяти: §5.5 говорит про 15 млн текстов,
        # а чтение файла целиком означало бы OOM ровно на заявленном масштабе.
        # Запись во временный файл с последующей атомарной заменой: падение
        # посреди таблицы больше не оставляет полуобработанный дамп.
        with gzip.open(path, "rt", encoding="utf-8", newline="") as fh, \
                gzip.open(tmp, "wt", encoding="utf-8", newline="") as out_fh:
            for line in fh:
                rows += 1
                if line.rstrip("\n") == "\\.":
                    out_fh.write(line)
                    continue
                fields = line.rstrip("\n").split("\t")
                if len(fields) < len(order):   # хвост файла / служебные строки
                    out_fh.write(line)
                    continue
                pk = fields[pk_idx]
                for i, qualified in idxs.items():
                    if fields[i] == "\\N":
                        continue
                    aggressive = plan.columns[qualified].sem_type == "address"
                    new, notes = ts.sanitize_text(_copy_unescape(fields[i]), aggressive)
                    # Политика длины исполняется, а не декларируется: замена адреса
                    # даёт +46 знаков, и переполнение раньше вылезало на pg_restore -
                    # то есть ПОСЛЕ того, как верификация показала «зелено».
                    limit = limits.get(qualified)
                    if limit and len(new) > limit:
                        policy = length_policy[qualified]
                        if policy == "truncate":
                            new = new[:limit]
                            notes = notes + ["truncated_to_column_length"]
                        else:
                            raise ValueError(
                                f"{qualified}: замена длиной {len(new)} не влезает в "
                                f"{limit}; length_policy=fail. Дальше: поставьте "
                                f"truncate в плане для этой колонки либо расширьте "
                                f"колонку в staging до прогона restore.")
                    fields[i] = _copy_escape(new)
                    for code in notes:
                        degraded += 1
                        notes_rows.append((table, pk, qualified.rsplit(".", 1)[1], code))
                out_fh.write("\t".join(fields) + "\n")
        tmp.replace(path)
        summary[table] = {"rows": rows, "degraded": degraded}
        files[table] = {"pre": files[table]["pre"], "post": _sha256(path)}
        # State и sanitization.sql переписываются после КАЖДОЙ таблицы, и state -
        # атомарно (tmp+replace) (ревью-2, Н1): раньше state писался один раз в
        # конце, и крах между mark("done") и той записью оставлял таблицу в
        # already_done, но вне summary - условие пропуска выше было ложно, и
        # перезапуск трансформировал её повторно (телефон уезжал в третье
        # значение). sanitization.sql пишется ИЗ накопленного state, поэтому
        # обязан переписываться в той же точке - иначе на диске жила бы пара
        # «новый state / старый sql».
        _write_state(state_path, notes_rows, summary, files)
        _write_sanitization_sql(dump_dir, notes_rows, summary)
        if runlog:
            runlog.mark("pass2", table, "done")

    _write_state(state_path, notes_rows, summary, files)
    _write_sanitization_sql(dump_dir, notes_rows, summary)
    return summary


def _sha256(path: Path) -> str:
    """Хэш файла потоком - .dat.gz таблицы может быть велик, в память не читаем."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_state(state_path: Path, notes_rows: list[tuple], summary: dict,
                 files: dict | None = None):
    """Атомарная запись накопленного состояния прохода 2: tmp + replace.
    Неатомарная запись при крахе оставила бы половину JSON, и возобновление
    стартовало бы с битого summary - то есть снова с повторной обработки.
    files: таблица -> {pre, post} хэши .dat.gz - защита окна краха (Н1)."""
    tmp = state_path.with_name(state_path.name + ".tmp")
    tmp.write_text(json.dumps({"notes": [list(n) for n in notes_rows],
                               "summary": summary,
                               "files": files or {}}, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(state_path)


def _completed_tables(runlog) -> set[str]:
    """Таблицы, уже обработанные в этом прогоне. Проход 2 неидемпотентен: телефон,
    заменённый однажды, при повторе заменяется снова и уезжает в третье значение."""
    if runlog is None:
        return set()
    run_id = (runlog.meta or {}).get("run_id")
    if not run_id:
        return set()
    last: dict[str, str] = {}
    for stage, tbl, status, _ in runlog.entries(run_id):
        if stage == "pass2":
            last[tbl] = status
    return {t for t, status in last.items() if status == "done"}


_UNESCAPE = {"t": "\t", "n": "\n", "r": "\r", "\\": "\\",
             "b": "\b", "f": "\f", "v": "\v"}


def _copy_unescape(s: str) -> str:
    """Один проход слева направо. Последовательные replace были неверны в
    принципе: «\\\\t» (литеральный слэш и буква t) сначала превращался в табуляцию,
    и текст с обратным слэшем портился безвозвратно.
    Помимо \\t\\n\\r pg_dump пишет \\b \\f \\v и восьмеричные \\ooo (ревью 2):
    незнакомая последовательность после round-trip превращалась в литеральные
    «\\»+«b» - молчаливая порча данных, которую не видит ни одна проверка."""
    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = s[i + 1] if i + 1 < len(s) else ""
        if nxt in _UNESCAPE:
            out.append(_UNESCAPE[nxt])
            i += 2
            continue
        # восьмеричный эскейп: 1-3 цифры (pg_dump пишет ровно три)
        j = i + 1
        while j < len(s) and j < i + 4 and s[j] in "01234567":
            j += 1
        if j > i + 1:
            out.append(chr(int(s[i + 1:j], 8)))
            i = j
            continue
        out.append("\\" + nxt)
        i += 2 if nxt else 1
    return "".join(out)


def _copy_escape(s: str) -> str:
    # \b \f \v эскейпим обратно теми же последовательностями, что пишет
    # pg_dump: литеральный 0x08 в COPY-потоке легален, но round-trip обязан
    # быть байт-в-байт обратимым, а не «легальным в среднем»
    return (s.replace("\\", "\\\\").replace("\t", "\\t")
             .replace("\n", "\\n").replace("\r", "\\r")
             .replace("\b", "\\b").replace("\f", "\\f").replace("\v", "\\v"))


def _q(value: str) -> str:
    """Строковый литерал SQL. Значения приходят из дампа: PK бывает текстовым, и
    апостроф внутри ломал sanitization.sql, который исполняется на staging."""
    return "'" + str(value).replace("'", "''") + "'"


def _write_sanitization_sql(dump_dir: Path, notes: list[tuple], summary: dict):
    """Примечания §5.7.1 внутри каталога дампа; применяются командой restore.
    Скрипт идемпотентен: restore на непустую staging повторяется без ошибок."""
    lines = [
        "CREATE SCHEMA IF NOT EXISTS sanitization;",
        "CREATE TABLE IF NOT EXISTS sanitization.notes "
        "(table_name text, row_pk text, column_name text, reason text);",
        "CREATE TABLE IF NOT EXISTS sanitization.summary "
        "(table_name text, rows int, degraded int);",
        "TRUNCATE sanitization.notes; TRUNCATE sanitization.summary;",
    ]
    if len(notes) <= 10_000:  # построчно только меньшинство (§5.7.1 п.3)
        for t, pk, col, code in notes:
            lines.append("INSERT INTO sanitization.notes VALUES "
                         f"({_q(t)}, {_q(pk)}, {_q(col)}, {_q(code)});")
    for t, s in summary.items():
        lines.append(f"INSERT INTO sanitization.summary VALUES "
                     f"({_q(t)}, {s['rows']}, {s['degraded']});")
    (dump_dir / "sanitization.sql").write_text("\n".join(lines), encoding="utf-8")




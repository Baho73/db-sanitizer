# START_MODULE_CONTRACT
#   PURPOSE: Интроспекция каталога Postgres: схема, ограничения, FK-граф (включая
#            композитные), статистика значений, ключи jsonb, разбираемость адресов.
#   SCOPE: Только чтение каталога и образцов; ничего не решает о стратегиях.
#   DEPENDS: none (psycopg - внешний)
#   LINKS: M-CLASSIFIER, M-FK-CLOSURE (потребители снимка), V-M-PROFILER
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ident - квотированный идентификатор SQL (схема.таблица, колонка)
#   ColumnInfo - колонка снимка
#   ForeignKey - связь
#   Snapshot - сериализуемый снимок схемы
#   profile - построить Snapshot по DSN
#   addr_parse_ratio - доля значений, разбираемых адресным мини-парсером
# END_MODULE_MAP
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field




def ident(name: str):
    """«схема.таблица» или имя колонки -> квотированный идентификатор.

    Интерполяция имён в f-строку работает ровно до первой колонки с именем
    `order`, `user`, CamelCase или пробелом: такие схемы роняли прогон, а на
    имени, совпавшем со служебным словом, могли и молча изменить смысл запроса."""
    from psycopg import sql

    return sql.SQL(".").join(sql.Identifier(p) for p in name.split("."))


@dataclass
class ColumnInfo:
    table: str
    name: str
    data_type: str
    max_len: int | None
    nullable: bool
    is_unique: bool
    is_pk: bool
    cardinality: int
    null_frac: float
    samples: list[str]
    json_keys: list[str] = field(default_factory=list)
    addr_parse_ratio: float | None = None

    @property
    def qualified(self) -> str:
        return f"{self.table}.{self.name}"


@dataclass
class ForeignKey:
    src_table: str
    src_cols: tuple[str, ...]
    dst_table: str
    dst_cols: tuple[str, ...]


@dataclass
class Snapshot:
    columns: list[ColumnInfo]
    fks: list[ForeignKey]
    row_counts: dict[str, int]

    def to_json(self) -> str:
        return json.dumps({"columns": [asdict(c) for c in self.columns],
                           "fks": [asdict(f) for f in self.fks],
                           "row_counts": self.row_counts}, ensure_ascii=False, indent=1, default=str)

    @staticmethod
    def from_json(raw: str) -> "Snapshot":
        """Обратная сериализация: продолжение прогона после гейта идёт в ДРУГОМ
        процессе, где модульного кэша снимка нет."""
        d = json.loads(raw)
        return Snapshot([ColumnInfo(**c) for c in d["columns"]],
                        [ForeignKey(f["src_table"], tuple(f["src_cols"]),
                                    f["dst_table"], tuple(f["dst_cols"])) for f in d["fks"]],
                        d["row_counts"])

    def col(self, qualified: str) -> ColumnInfo:
        return next(c for c in self.columns if c.qualified == qualified)





# Мини-парсер адреса для метрики разбираемости (§3.2 п.1). Не нормализует -
# только решает, укладывается ли строка в «регион?/город/улица/дом» без остатка.
_ADDR_PART = re.compile(
    r"^\s*(?:[а-яё\- ]+област[ьи]|г\.?\s*[а-яё\-]+|[а-яё\-]{3,}|ул\.?\s*[а-яё\- ]+|д\.?\s*\d+[а-я]?|кв\.?\s*\d+|\d+[а-я]?)\s*$",
    re.IGNORECASE)


def addr_parse_ratio(values: list[str]) -> float:
    if not values:
        return 1.0
    ok = sum(1 for v in values if v and all(_ADDR_PART.match(p) for p in v.split(",")))
    return ok / len(values)






_COLS_SQL = """
SELECT c.table_schema || '.' || c.table_name, c.column_name, c.data_type,
       c.character_maximum_length, c.is_nullable = 'YES'
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE c.table_schema = %s AND t.table_type = 'BASE TABLE'
ORDER BY c.table_name, c.ordinal_position"""

_CONSTRAINTS_SQL = """
SELECT tc.table_schema || '.' || tc.table_name, kcu.column_name, tc.constraint_type
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu ON kcu.constraint_name = tc.constraint_name
 AND kcu.table_schema = tc.table_schema AND kcu.table_name = tc.table_name
WHERE tc.table_schema = %s AND tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE')"""
# table_name в join обязателен: имя ограничения уникально только внутри таблицы.
# Без него FK, названный как PK соседней таблицы, порождает строку-фантом и
# помечает чужую колонку как первичный ключ (разбор 4, находка 2).

# pg_constraint вместо information_schema: constraint_column_usage теряет порядок
# колонок и даёт декартово произведение на композитных FK.
# Схема сравнивается через pg_namespace.nspname, а не через regnamespace::text:
# последний квотирует имя («"My Schema"»), сравнение с сырым именем молча не
# совпадало бы, и FK-граф оказался бы неполным - то есть классы эквивалентности
# распались бы, а замены разъехались.
_FK_SQL = """
SELECT sn.nspname || '.' || src.relname,
       (SELECT array_agg(a.attname ORDER BY x.ord)
        FROM unnest(c.conkey) WITH ORDINALITY x(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = x.attnum),
       dn.nspname || '.' || dst.relname,
       (SELECT array_agg(a.attname ORDER BY x.ord)
        FROM unnest(c.confkey) WITH ORDINALITY x(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = x.attnum)
FROM pg_constraint c
JOIN pg_class src ON src.oid = c.conrelid
JOIN pg_class dst ON dst.oid = c.confrelid
JOIN pg_namespace sn ON sn.oid = src.relnamespace
JOIN pg_namespace dn ON dn.oid = dst.relnamespace
WHERE c.contype = 'f' AND sn.nspname = %s"""


# START_CONTRACT: profile
#   PURPOSE: Снимок схемы и статистики; детерминирован на неизменной базе.
#   INPUTS: { dsn: str, schema: str, sample_n: int - образцов на колонку }
#   OUTPUTS: { Snapshot }
#   SIDE_EFFECTS: только чтение БД
# END_CONTRACT: profile
def profile(dsn: str, schema: str = "hr", sample_n: int = 50) -> Snapshot:
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(_COLS_SQL, (schema,))
        raw_cols = cur.fetchall()

        cur.execute(_CONSTRAINTS_SQL, (schema,))
        uniq: set[tuple[str, str]] = set()
        pk: set[tuple[str, str]] = set()
        for tbl, col, kind in cur.fetchall():
            (pk if kind == "PRIMARY KEY" else uniq).add((tbl, col))

        cur.execute(_FK_SQL, (schema,))
        fks = [ForeignKey(src_t, tuple(src_cols), dst_t, tuple(dst_cols))
               for src_t, src_cols, dst_t, dst_cols in cur.fetchall()]

        # одна статистика на таблицу вместо трёх запросов на колонку
        by_table: dict[str, list[tuple]] = {}
        for row in raw_cols:
            by_table.setdefault(row[0], []).append(row)
        row_counts: dict[str, int] = {}
        stats: dict[tuple[str, str], tuple[int, float]] = {}
        columns: list[ColumnInfo] = []
        from psycopg import sql

        for tbl, cols in sorted(by_table.items()):
            exprs = sql.SQL(", ").join(
                sql.SQL("count(DISTINCT {c}::text), avg(({c} IS NULL)::int)::float")
                .format(c=ident(n)) for _, n, *_ in cols)
            cur.execute(sql.SQL("SELECT count(*), {} FROM {}").format(exprs, ident(tbl)))
            row = cur.fetchone()
            row_counts[tbl] = row[0]
            for i, (_, name, *_) in enumerate(cols):
                stats[(tbl, name)] = (row[1 + 2 * i] or 0, row[2 + 2 * i] or 0.0)

        for tbl, name, dtype, max_len, nullable in raw_cols:
            card, null_frac = stats[(tbl, name)]
            cur.execute(sql.SQL("SELECT DISTINCT {c}::text FROM {t} WHERE {c} IS NOT NULL "
                                "ORDER BY 1 LIMIT %s").format(c=ident(name), t=ident(tbl)),
                        (sample_n,))
            samples = [r[0] for r in cur.fetchall()]
            info = ColumnInfo(tbl, name, dtype, max_len, nullable,
                              (tbl, name) in uniq, (tbl, name) in pk,
                              card or 0, null_frac or 0.0, samples)
            if dtype == "jsonb":
                # ORDER BY обязателен: без него набор ключей плавал между
                # прогонами, отпечаток схемы становился недетерминированным, а
                # ключи вне выборки молча обнулялись на исполнении
                cur.execute(sql.SQL("SELECT DISTINCT jsonb_object_keys({c}) FROM {t} "
                                    "WHERE {c} IS NOT NULL ORDER BY 1 LIMIT 500")
                            .format(c=ident(name), t=ident(tbl)))
                info.json_keys = sorted(r[0] for r in cur.fetchall())
            if dtype in ("character varying", "text") and _looks_addressish(name, samples):
                info.addr_parse_ratio = addr_parse_ratio(samples)
            columns.append(info)

    return Snapshot(columns, fks, row_counts)


def _looks_addressish(name: str, samples: list[str]) -> bool:
    if re.search(r"addr|адрес|city|город", name, re.I):
        return True
    joined = " ".join(samples[:20]).lower()
    return sum(w in joined for w in ("ул.", "область", " г. ", "кв ")) >= 2




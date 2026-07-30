# START_MODULE_CONTRACT
#   PURPOSE: Cmd-процесс для Greenmask (json-драйвер): построчная трансформация
#            структурных колонок по плану. Все классы эквивалентности и
#            идентичностные типы идут только здесь (§5.1, правило единого движка).
#   SCOPE: stdin/stdout протокол {"col": {"d": ..., "n": ...}}; никакого сетевого
#          I/O; LLM отсутствует - только план, корпуса, соль, предвычисленные карты.
#   DEPENDS: M-MAPPER, M-CORPUS, M-POLICY (модель плана)
#   LINKS: M-EXECUTOR (генерирует конфиг, запускает процесс), V-M-EXECUTOR
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   RowTransformer - собранное из плана построчное преобразование
#   transform_line - одна строка протокола -> одна строка протокола
#   main - цикл stdin/stdout
# END_MODULE_MAP
from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path

from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import (
    Mapper, Salt, gen_digits_like, gen_inn12, gen_int_in_range, gen_ogrn, gen_snils,
    normalize_digits,
)
from sanitizer.policy import Plan




class RowTransformer:
    def __init__(self, plan: Plan, table: str, salt: Salt, corpora: dict[str, list[str]],
                 artifacts_dir: Path):
        self.salt = salt
        self.mapper = Mapper(salt, corpora)
        self.table = table
        self.cols = {name.rsplit(".", 1)[1]: pc for name, pc in plan.columns.items()
                     if name.rsplit(".", 1)[0] == table}
        self.direct: dict[str, dict[str, str]] = {}
        self.shuffle: dict[str, dict[str, str]] = {}
        for col, pc in self.cols.items():
            if pc.strategy == "direct":
                self.direct[col] = json.loads(
                    (artifacts_dir / f"direct.{table}.{col}.json").read_text(encoding="utf-8"))
            elif pc.strategy == "shuffle":
                self.shuffle[col] = json.loads(
                    (artifacts_dir / f"shuffle.{table}.{col}.json").read_text(encoding="utf-8"))

    # START_CONTRACT: transform_row
    #   PURPOSE: Замены по стратегиям плана; ФИО-компоненты согласованы в
    #            пределах строки (род, единый ключ идентичности).
    #   INPUTS: { row: dict col->{"d": str|None, "n": bool}, pk: str - значение PK }
    #   OUTPUTS: { dict той же формы }
    #   SIDE_EFFECTS: none
    # END_CONTRACT: transform_row
    def transform_row(self, row: dict, pk: str = "") -> dict:
        out = dict(row)
        fio = self._fio_columns(row)
        if fio:
            last_c, first_c, mid_c = fio
            f, n, p = self.mapper.fio(_d(row, last_c), _d(row, first_c), _d(row, mid_c))
            _set(out, last_c, f.capitalize())
            _set(out, first_c, n.capitalize())
            _set(out, mid_c, p.capitalize())
        for col, pc in self.cols.items():
            if col not in row or row[col].get("n") or (fio and col in fio):
                continue
            val = row[col]["d"]
            match pc.strategy:
                case "keep" | "freetext" | "unresolved":
                    pass  # freetext - проход 2; unresolved сюда не доходит (валидация)
                case "generate":
                    _set(out, col, self._generate(pc.sem_type, val))
                case "fake":
                    _set(out, col, self._fake(pc.sem_type, val))
                case "direct":
                    _set(out, col, self.direct[col][val])  # KeyError = data drift, fail-closed
                case "shuffle":
                    _set(out, col, self.shuffle[col][pk])
                case "generalize":
                    _set(out, col, self._generalize(pc.sem_type, val))
                case "null":
                    out[col] = {"d": None, "n": True}
                case "jsonb":
                    _set(out, col, self._jsonb(val, pc.json_fields))
        return out

    def _fio_columns(self, row) -> tuple[str, str, str] | None:
        by_type = {self.cols[c].sem_type: c for c in row if c in self.cols
                   and self.cols[c].strategy == "fake"}
        if "family" in by_type:
            return (by_type["family"], by_type.get("name", ""), by_type.get("patronymic", ""))
        return None

    def _generate(self, sem_type: str, val: str) -> str:
        match sem_type:
            case "inn":
                return gen_inn12(self.salt, val) if len(normalize_digits(val)) > 10 \
                    else gen_digits_like(self.salt, val)
            case "snils":
                return gen_snils(self.salt, val)
            case "ogrn":
                return gen_ogrn(self.salt, val, ip=len(normalize_digits(val)) == 15)
            case "email":
                return self.mapper.email(val)
            case "person_id":
                return str(gen_int_in_range(self.salt, val, 100000, 999999))
            case _:  # passport и прочие форматные номера
                return gen_digits_like(self.salt, val)

    def _fake(self, sem_type: str, val: str) -> str:
        m = self.mapper
        match sem_type:
            case "phone":
                return m.phone(val)
            case "city":
                return m.address_component("city", val).title()
            case "region":
                return m.address_component("region", val).title()
            case "org_name":
                return m.pick("org", val.lower(), avoid=val).upper()[:160]
            case "address":
                return self._fake_address(val)
            case "family" | "name" | "patronymic":
                f, n, p = m.fio(val if sem_type == "family" else "",
                                val if sem_type == "name" else "",
                                val if sem_type == "patronymic" else "")
                return (f or n or p).capitalize()
            case _:
                return m.pick("org", val.lower(), avoid=val)

    def _fake_address(self, val: str) -> str:
        """Покомпонентная замена валидного адреса: регион/город/улица из корпусов,
        дом детерминированно. Формат «обл, г. X, ул. Y, д. N»."""
        m = self.mapper
        region = m.address_component("region", val).title()
        city = m.address_component("city", val + "|c").title()
        street = m.address_component("street", val + "|s").title()
        house = gen_int_in_range(self.salt, val, 1, 99)
        return f"{region}, г. {city}, ул. {street}, д. {house}"

    def _generalize(self, sem_type: str, val: str) -> str:
        if sem_type == "birth_date":
            return f"{date.fromisoformat(val[:10]).year}-01-01"  # тип сохранён (§5.3)
        return val

    def _jsonb(self, val: str, fields: dict[str, str]) -> str:
        data = json.loads(val)
        for key, ftype in fields.items():
            if key not in data or data[key] is None:
                continue
            match ftype:
                case "phone":
                    data[key] = self.mapper.phone(str(data[key]))
                case "fio_full":
                    parts = str(data[key]).split()
                    f, n, p = self.mapper.fio(*(parts + ["", "", ""])[:3])
                    data[key] = " ".join(x.capitalize() for x in (f, n, p) if x)
                case "keep":
                    pass
                case _:
                    data[key] = ""  # неизвестная разметка не пропускает данные
        return json.dumps(data, ensure_ascii=False)


def _d(row: dict, col: str) -> str:
    return (row.get(col) or {}).get("d") or ""


def _set(out: dict, col: str, value: str):
    if col:
        out[col] = {"d": value, "n": False}







def transform_line(t: RowTransformer, line: str, pk_col: str) -> str:
    row = json.loads(line)
    pk = _d(row, pk_col) if pk_col else ""
    return json.dumps(t.transform_row(row, pk), ensure_ascii=False)


def main() -> int:
    import argparse
    import signal

    # Greenmask завершает Cmd-процесс сигналом SIGTERM и ожидает exit code 0
    # (параметр expected_exit_code); питон по умолчанию умирает кодом -15.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--pk", default="id")
    ap.add_argument("--components", default="sanitizer/data/components-ru.json")
    ap.add_argument("--artifacts", default="out/artifacts")
    a = ap.parse_args()

    salt = Salt(master=os.environ.get("MASTER_SALT", "dev-master").encode(),
                recipient=os.environ.get("RECIPIENT", "dev"),
                generation=os.environ.get("GENERATION", "g1"),
                version=int(os.environ.get("MASTER_SALT_VERSION", "1")))
    t = RowTransformer(Plan.load(Path(a.plan)), a.table, salt,
                       build_corpora(load_components(Path(a.components))), Path(a.artifacts))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        # первая строка от Greenmask - метаданные таблицы, не данные:
        # у строки данных каждое значение - объект {"d": ..., "n": ...}
        if not all(isinstance(v, dict) and ("d" in v or "n" in v) for v in parsed.values()):
            continue
        print(transform_line(t, line, a.pk), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())



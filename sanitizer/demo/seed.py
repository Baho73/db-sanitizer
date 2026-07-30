# START_MODULE_CONTRACT
#   PURPOSE: Генерация синтетической «прод-базы» с враждебными случаями §7
#            и канареечным набором. Детерминирована по seed.
#   SCOPE: Порождает данные и манифест канареек; пишет в Postgres через psycopg.
#          Никаких реальных ПДн - только Faker и списки компонент.
#   DEPENDS: none (faker, psycopg - внешние)
#   LINKS: M-VERIFIER (читает canaries.json), V-M-DEMO-DB
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SCALES - профили масштаба (small по умолчанию, medium/large флагом)
#   CANARIES - атомарные канареечные образцы ПДн для верификатора
#   Rows - таблицы прогона + манифест канареек
#   generate_rows - все таблицы + канарейки, детерминированно по seed
#   seed_db - DDL + COPY в Postgres, пишет canaries.json
# END_MODULE_MAP
from __future__ import annotations

import io
import json
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from faker import Faker

from sanitizer.mapper import gen_inn12, gen_ogrn, gen_snils, Salt

SCALES = {  # employees, tickets, comments_per_ticket
    "small": (2_000, 4_000, 2),
    "medium": (20_000, 40_000, 3),
    "large": (100_000, 200_000, 3),
}

_GRADES = ["J1", "J2", "M1", "M2", "S1", "S2", "L1"]
_SEED_SALT = Salt(b"demo-seed-not-secret", "seed", "seed")  # только валидные форматы для демо-данных


# Канарейки: известные образцы, которые верификатор обязан найти в исходной базе
# (K из K) и не найти в санитизированной (0 из K). Включая jsonb, текст, склейку
# и хвост грязного адреса (§5.4, §7).
CANARIES = {
    "fio_employee": "Канарейкин Тестослав Проверович",
    "phone_jsonb": "+79997770001",
    "inn_soft_link": "770712345670",
    "email_unique": "kanareykin.t@canary-demo.ru",
    "passport_doc": "4501 123456",
    "fio_phone_glued": "Канарейкина В.П., тел. 8-999-777-00-02",
    # Канарейки грязного адреса АТОМАРНЫ. Составная строка («имя + домофон»)
    # проходила проверку при замене одного лишь имени, пока адрес и код домофона
    # утекали — проверка, которую удовлетворяет частичное исправление, бесполезна.
    "dirty_addr_name": "Марью Канареевну",
    "dirty_addr_domofon": "домофон 7701",
    "dirty_addr_street": "тверскя 5 кв 12",
    "snils_in_text": "123-456-789 64",
}



@dataclass
class Rows:
    tables: dict[str, list[tuple]] = field(default_factory=dict)
    canaries: dict[str, str] = field(default_factory=dict)


# START_CONTRACT: generate_rows
#   PURPOSE: Полный набор строк демо-базы, детерминированный по seed.
#   INPUTS: { scale: str - ключ SCALES, seed: int }
#   OUTPUTS: { Rows - таблицы в порядке вставки + манифест канареек }
#   SIDE_EFFECTS: none
# END_CONTRACT: generate_rows
def generate_rows(scale: str = "small", seed: int = 42) -> Rows:
    n_emp, n_tickets, n_cmt = SCALES[scale]
    fake = Faker("ru_RU")
    Faker.seed(seed)
    rnd = random.Random(seed)
    out = Rows(canaries=dict(CANARIES))

    regions = [(i + 1, name) for i, name in enumerate(
        ["Тверская область", "Калужская область", "Рязанская область", "Тульская область",
         "Владимирская область", "Ярославская область", "Смоленская область", "Брянская область"])]
    departments = [(i + 1, f"Департамент {w}", rnd.randint(1, len(regions)))
                   for i, w in enumerate(["производства", "логистики", "закупок", "качества",
                                          "ИТ", "персонала", "финансов", "сбыта", "энергетики", "ремонтов"])]
    positions = [(i + 1, t, rnd.choice(_GRADES)) for i, t in enumerate(
        ["Инженер-технолог", "Ведущий инженер", "Мастер участка", "Специалист по закупкам",
         "Аналитик", "Бухгалтер", "Электромонтёр", "Начальник смены", "Лаборант", "Диспетчер",
         "Инженер по охране труда", "Кладовщик"])]

    employees, addresses, documents = [], [], []
    for i in range(1, n_emp + 1):
        male = rnd.random() < 0.55
        last = fake.last_name_male() if male else fake.last_name_female()
        first = fake.first_name_male() if male else fake.first_name_female()
        middle = fake.middle_name_male() if male else fake.middle_name_female()
        inn = gen_inn12(_SEED_SALT, f"emp{i}")
        snils = gen_snils(_SEED_SALT, f"emp{i}")
        phone = f"+79{rnd.randint(0, 9)}{rnd.randint(1000000, 9999999)}{rnd.randint(10, 99)}"[:12]
        email = f"user{i}.{fake.slug()[:8]}@corp-demo.ru"[:120]
        attrs = json.dumps({"phone": phone, "emergency": fake.name(), "note": fake.word()},
                           ensure_ascii=False)
        employees.append((i, 100000 + i, last, first, middle,
                          fake.date_of_birth(minimum_age=20, maximum_age=60), inn, snils,
                          f"{rnd.randint(40, 45)}{rnd.randint(10, 25)}", f"{rnd.randint(100101, 999999)}",
                          phone, email, rnd.randint(400, 3200) * 100, rnd.randint(1, 7),
                          attrs, rnd.randint(1, len(departments)), rnd.randint(1, len(positions)),
                          fake.date_between(date(2010, 1, 1), date(2025, 12, 1))))
        if rnd.random() < 0.3:  # часть адресов - грязные строки
            addresses.append((len(addresses) + 1, i,
                              f"{fake.city()}, {fake.street_name()} {rnd.randint(1, 99)} кв {rnd.randint(1, 200)}"
                              + (f", спросить {fake.name()}, домофон {rnd.randint(1000, 9999)}"
                                 if rnd.random() < 0.4 else "")))
        else:
            addresses.append((len(addresses) + 1, i,
                              f"{fake.region()}, г. {fake.city()}, ул. {fake.street_name()}, д. {rnd.randint(1, 99)}"))
        documents.append((len(documents) + 1, i, "passport",
                          f"{rnd.randint(4000, 4599)} {rnd.randint(100101, 999999)}"))

    # канарейки в employees / addresses / documents
    cid = n_emp + 1
    employees.append((cid, 100000 + cid, "Канарейкин", "Тестослав", "Проверович",
                      date(1985, 3, 14), CANARIES["inn_soft_link"], gen_snils(_SEED_SALT, "canary"),
                      "4501", "123456", "+79997770009", CANARIES["email_unique"],
                      150000, 3, json.dumps({"phone": CANARIES["phone_jsonb"]}, ensure_ascii=False),
                      1, 1, date(2020, 1, 15)))
    addresses.append((len(addresses) + 1, cid,
                      f"мск, {CANARIES['dirty_addr_street']}, спросить "
                      f"{CANARIES['dirty_addr_name']}, {CANARIES['dirty_addr_domofon']}"))
    documents.append((len(documents) + 1, cid, "passport", CANARIES["passport_doc"]))

    contractors = [(i + 1, f"ООО {fake.company()}"[:160], gen_inn12(_SEED_SALT, f"c{i}"),
                    f"{rnd.randint(770101001, 779999999)}", gen_ogrn(_SEED_SALT, f"c{i}"),
                    f"{fake.region()}, г. {fake.city()}, ул. {fake.street_name()}, д. {rnd.randint(1, 60)}")
                   for i in range(60)]
    contractors.append((61, "ООО Канареечный контрагент", CANARIES["inn_soft_link"],
                        "770101001", gen_ogrn(_SEED_SALT, "canary-c"),
                        "Тверская область, г. Ржев, ул. Садовая, д. 5"))

    contracts = [(i + 1, f"Д-{rnd.randint(2018, 2026)}/{rnd.randint(1, 999):03d}",
                  contractors[rnd.randint(0, len(contractors) - 1)][2],
                  rnd.randint(1, n_emp), rnd.randint(100, 90000) * 1000,
                  fake.date_between(date(2018, 1, 1), date(2026, 6, 1)))
                 for i in range(max(200, n_emp // 10))]

    contract_items, shipments = [], []
    for c_id in range(1, len(contracts) + 1):
        for item in range(1, rnd.randint(2, 4)):
            contract_items.append((c_id, item, fake.bs()[:200], rnd.randint(1, 500)))
            if rnd.random() < 0.5:
                shipments.append((len(shipments) + 1, c_id, item,
                                  fake.date_between(date(2019, 1, 1), date(2026, 6, 1))))

    tickets, comments = [], []
    for t in range(1, n_tickets + 1):
        emp = rnd.randint(1, n_emp)
        body = rnd.choice([
            f"Прошу оформить пропуск. Контакт: {fake.name()}, тел {fake.phone_number()}.",
            f"Не работает почта {fake.email()}, откатите настройки.",
            f"Сверьте СНИЛС {gen_snils(_SEED_SALT, f't{t}')} в личном деле.",
            f"Заявка от {fake.name()}: заменить пропуск, паспорт {rnd.randint(4000, 4599)} {rnd.randint(100101, 999999)}.",
            "Плановое обслуживание станка, без персональных данных.",
        ])
        tickets.append((t, emp, fake.catch_phrase()[:200], body))
        for _ in range(n_cmt):
            author = rnd.randint(1, n_emp)
            comments.append((len(comments) + 1, t, author, rnd.choice([
                f"{fake.last_name()} {fake.first_name()[0]}.{fake.middle_name()[0]}., тел. {fake.phone_number()}"[:400],
                f"Согласовано, направил {fake.first_name()} {fake.last_name()}",
                "Принято в работу.",
            ])))
    tickets.append((n_tickets + 1, cid, "Канареечная заявка",
                    f"Обращение от {CANARIES['fio_employee']}, СНИЛС {CANARIES['snils_in_text']}."))
    comments.append((len(comments) + 1, n_tickets + 1, cid, CANARIES["fio_phone_glued"]))

    payroll = [(0, e_id, date(2024 + (m - 1) // 12, (m - 1) % 12 + 1, 1), rnd.randint(400, 3200) * 100)
               for e_id in range(1, min(n_emp, 2000) + 1) for m in range(1, 25)]
    payroll = [(i + 1, *row[1:]) for i, row in enumerate(payroll)]
    audit = [(i + 1, rnd.randint(1, n_emp), rnd.choice(["login", "update", "export"]),
              datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=i))
             for i in range(min(n_emp * 2, 10_000))]

    out.tables = {
        "hr.regions": regions, "hr.departments": departments, "hr.positions": positions,
        "hr.employees": employees, "hr.addresses": addresses, "hr.documents": documents,
        "hr.contractors": contractors, "hr.contracts": contracts,
        "hr.contract_items": contract_items, "hr.shipments": shipments,
        "hr.tickets": tickets, "hr.ticket_comments": comments,
        "hr.payroll": payroll, "hr.audit_log": audit,
    }
    return out





def seed_db(dsn: str, scale: str = "small", seed: int = 42,
            canary_path: Path = Path("out/canaries.json")) -> dict[str, int]:
    """DDL + COPY. Возвращает счётчики строк по таблицам."""
    import psycopg

    rows = generate_rows(scale, seed)
    ddl = (Path(__file__).parent / "ddl.sql").read_text(encoding="utf-8")
    counts: dict[str, int] = {}
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS hr CASCADE")
            cur.execute(ddl)
            for table, data in rows.tables.items():
                buf = io.StringIO()
                for r in data:
                    buf.write("\t".join(_pg_text(v) for v in r) + "\n")
                buf.seek(0)
                with cur.copy(f"COPY {table} FROM STDIN") as copy:
                    copy.write(buf.read())
                counts[table] = len(data)
                cur.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                            f"(SELECT COALESCE(MAX(id),1) FROM {table}))") if _has_id(table) else None
        conn.commit()
    canary_path.parent.mkdir(parents=True, exist_ok=True)
    n_emp = SCALES[scale][0]
    manifest = {"values": rows.canaries,
                "employee_id": n_emp + 1,
                "ticket_id": SCALES[scale][1] + 1,
                "expected_family_lemma": "канарейкин"}
    canary_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    return counts


def _has_id(table: str) -> bool:
    return table not in ("hr.contract_items",)


def _pg_text(v) -> str:
    if v is None:
        return "\\N"
    s = str(v)
    return s.replace("\\", "\\\\").replace("\t", " ").replace("\n", " ")




if __name__ == "__main__":
    import argparse
    import os

    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["seed"])
    ap.add_argument("--scale", default="small", choices=list(SCALES))
    ap.add_argument("--dsn", default=os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo"))
    a = ap.parse_args()
    print(json.dumps(seed_db(a.dsn, a.scale), indent=1))

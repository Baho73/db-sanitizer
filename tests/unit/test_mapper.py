# Property-тесты M-MAPPER: детерминизм, консистентность форм, fake(x)!=x,
# уникальность generate, несвязываемость солей, контрольные суммы. (T-001)
import random

from sanitizer.mapper import (
    Mapper, Salt, feminize, gen_digits_like, gen_inn10, gen_inn12, gen_int_in_range,
    gen_ogrn, gen_snils, normalize_email, normalize_fio, normalize_phone,
    valid_inn, valid_ogrn, valid_snils,
)

SALT = Salt(master=b"test-master", recipient="dev", generation="g1")
SALT2 = Salt(master=b"test-master", recipient="contractor", generation="g1")

CORPORA = {
    "family": ["кузнецов", "смирнов", "попов", "васильев", "соколов", "михайлов", "фёдоров", "морозов"],
    "name_m": ["алексей", "дмитрий", "сергей", "андрей", "николай"],
    "name_f": ["елена", "ольга", "наталья", "ирина", "татьяна"],
    "patronymic_m": ["алексеевич", "дмитриевич", "сергеевич", "андреевич"],
    "patronymic_f": ["алексеевна", "дмитриевна", "сергеевна", "андреевна"],
    "phone_code": ["905", "916", "926", "981"],
    "email_domain": ["example.org", "test.ru"],
    "city": ["тверь", "калуга", "рязань", "тула"],
    "region": ["тверская область", "калужская область"],
    "street": ["садовая", "лесная", "центральная", "школьная"],
}
M = Mapper(SALT, CORPORA)
M2 = Mapper(SALT2, CORPORA)


def test_determinism():
    assert M.fio("Петров", "Иван", "Иванович") == M.fio("Петров", "Иван", "Иванович")
    assert M.phone("8 (905) 123-45-67") == M.phone("8 (905) 123-45-67")


def test_identity_key_forms():
    # разные формы записи одной сущности -> одна замена (§3.2)
    a = M.fio("ПЕТРОВ", "Иван", "Иванович")
    b = M.fio("петров", "иван", "иванович")
    c = M.fio("Пётров".replace("ё", "е"), "Иван", "Иванович")
    assert a == b == c
    assert M.phone("8-905-123-45-67") == M.phone("+7 905 1234567")
    assert M.email("Ivan.Petrov+tag@Mail.RU") == M.email("ivan.petrov@mail.ru")


def test_family_consistency_across_gender():
    # Петров и Петрова - одна фамильная лемма -> один фейк-корень, род сохранён
    m_f, _, _ = M.fio("Петров", "Иван", "Иванович")
    f_f, _, _ = M.fio("Петрова", "Анна", "Ивановна")
    assert feminize(m_f) == f_f


def test_initials_follow_family():
    full = M.fio("Петров", "Иван", "Иванович")
    fam, i1, i2 = M.initials("Петров", "и", "и")
    assert fam == full[0]  # фамильный компонент консистентен (§3.2, критерий §7)
    assert len(i1) == 1 and len(i2) == 1


def test_fake_neq_source():
    # fake(x) != x, включая значение, чей фейк по хэшу попал бы в себя
    for fam in CORPORA["family"]:
        out, _, _ = M.fio(fam.capitalize(), "Иван", "Иванович")
        assert out != fam


def test_unlinkability_of_recipients():
    assert M.fio("Петров", "Иван", "Иванович") != M2.fio("Петров", "Иван", "Иванович") or \
           M.phone("+79051234567") != M2.phone("+79051234567")


def test_generate_checksums():
    for i in range(200):
        assert valid_inn(gen_inn10(SALT, f"77{i:08d}"))
        assert valid_inn(gen_inn12(SALT, f"5008{i:08d}"))
        assert valid_snils(gen_snils(SALT, f"{i:011d}"))
        assert valid_ogrn(gen_ogrn(SALT, f"1{i:012d}"))
        assert valid_ogrn(gen_ogrn(SALT, f"3{i:014d}", ip=True))


def test_generate_uniqueness_100k():
    seen = {gen_inn12(SALT, str(i)) for i in range(100_000)}
    assert len(seen) == 100_000


def test_int_in_range_unique_for_unique_sources():
    # табельные номера под UNIQUE: 2001 исходник -> 2001 уникальная замена
    outs = {gen_int_in_range(SALT, str(100000 + i), 100000, 999999) for i in range(2001)}
    assert len(outs) == 2001
    emails = {M.email(f"user{i}@corp-demo.ru") for i in range(2001)}
    assert len(emails) == 2001


def test_int_in_range_and_digits_like():
    rnd = random.Random(7)
    for _ in range(500):
        lo, hi = sorted(rnd.sample(range(1, 10_000), 2))
        v = gen_int_in_range(SALT, str(rnd.random()), lo, hi)
        assert lo <= v <= hi
    src = "Д-2024/117-А"
    out = gen_digits_like(SALT, src)
    assert out != src
    assert [ch.isdigit() for ch in out] == [ch.isdigit() for ch in src]
    assert all(a == b for a, b in zip(out, src) if not a.isdigit() and not b.isdigit())


def test_normalize_gender_detection():
    assert normalize_fio("Донская", "Анна", "")[3] == "f"
    assert normalize_fio("Петров", "Иван", "Иванович")[3] == "m"
    assert normalize_fio("Петрова", "", "")[0] == "петров"


def test_phone_email_shapes():
    p = M.phone("89051234567")
    assert p.startswith("+7") and len(p) == 12
    e = M.email("ivan@corp.ru")
    assert "@" in e and e.split("@")[1] in CORPORA["email_domain"]
    assert e != normalize_email("ivan@corp.ru")


def test_address_components():
    assert M.address_component("city", "Тверь") != "тверь"
    assert M.address_component("city", "Тверь") == M.address_component("city", "ТВЕРЬ")

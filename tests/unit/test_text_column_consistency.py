# Свойственные тесты сквозной консистентности «колонка ↔ свободный текст».
#
# Разбор 6 показал, чем плох одиночный пример: тест «телефон не заменяется
# дважды» брал ОДНО число в ОДНОМ написании и был зелёным, пока 10% номеров в
# форме «+7 XXX XXX-XX-XX» уезжали через генератор ИНН - у них внутренние
# десять цифр случайно проходят контрольную сумму. Дефект класса «доля»
# одиночным примером не ловится физически. (T-112)
import random

import pytest

from pathlib import Path

from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import (
    Mapper, Salt, gen_digits_like, gen_snils, normalize_digits, normalize_phone,
)
from sanitizer.postproc import TextSanitizer

S = Salt(b"consistency", "d", "g")
M = Mapper(S, build_corpora(load_components(Path("sanitizer/data/components-ru.json"))))
TS = TextSanitizer(M, S, frozenset())
N = 400          # хватает, чтобы поймать долю в 0.5%; прогон - доли секунды

PHONE_SHAPES = [
    "+7 {a} {b}-{c}-{d}",
    "+7 ({a}) {b}-{c}-{d}",
    "8 {a} {b}-{c}-{d}",
    "8 ({a}) {b}-{c}-{d}",
    "8-{a}-{b}-{c}-{d}",
    "+7{a}{b}{c}{d}",
]


def _phones(seed=11):
    rnd = random.Random(seed)
    for _ in range(N):
        yield (f"{rnd.randint(900, 999)}", f"{rnd.randint(100, 999)}",
               f"{rnd.randint(10, 99)}", f"{rnd.randint(10, 99)}")


@pytest.mark.parametrize("shape", PHONE_SHAPES)
def test_phone_in_text_matches_column_replacement(shape):
    """Номер в тексте обязан получить ТУ ЖЕ замену, что в структурной колонке,
    в любом написании с телефонной разметкой. Колонка про контрольные суммы не
    знает и всегда идёт через mapper.phone - расхождение нарушает §3.2."""
    bad = []
    for a, b, c, d in _phones():
        written = shape.format(a=a, b=b, c=c, d=d)
        expected = M.phone("8" + a + b + c + d)
        got, _ = TS.sanitize_text(f"звонить {written}")
        if normalize_phone(got.split(" ", 1)[1]) != normalize_phone(expected):
            bad.append((written, got))
    assert not bad, f"{len(bad)} из {N}: {bad[:3]}"


def test_passport_in_text_matches_column_replacement():
    rnd = random.Random(12)
    bad = []
    for _ in range(N):
        written = f"{rnd.randint(4000, 4599)} {rnd.randint(100000, 999999)}"
        got, _ = TS.sanitize_text(f"паспорт {written}")
        if got.split(" ", 1)[1] != gen_digits_like(S, written):
            bad.append(written)
    assert not bad, f"{len(bad)} из {N}: {bad[:3]}"


def test_snils_in_text_matches_column_replacement():
    bad = []
    for i in range(N):
        src = gen_snils(S, f"person{i}")
        got, _ = TS.sanitize_text(f"СНИЛС {src}")
        if normalize_digits(got) != normalize_digits(gen_snils(S, src)):
            bad.append(src)
    assert not bad, f"{len(bad)} из {N}: {bad[:3]}"


def test_bare_eleven_digits_are_decided_by_checksum():
    """Голая последовательность цифр не несёт разметки, и единственное
    доступное свидетельство - контрольная сумма. Двусмысленность «номер или
    идентификатор» здесь неустранима; правило объявлено, а не случайно."""
    snils = gen_snils(S, "bare")
    got, _ = TS.sanitize_text(f"номер {snils}")
    assert normalize_digits(got) == normalize_digits(gen_snils(S, snils))
    # телефон без разметки, чьи цифры контрольную сумму НЕ проходят - телефон
    plain = "89161234500"
    got, _ = TS.sanitize_text(f"тел {plain}")
    assert M.phone(plain) in got


def test_identifiers_still_replaced_after_priority_change():
    """Правка приоритета не должна была ослабить распознавание идентификаторов."""
    from sanitizer.mapper import gen_inn10, gen_inn12, gen_ogrn, valid_inn, valid_ogrn

    for i in range(100):
        for src, ok in ((gen_inn10(S, f"a{i}"), valid_inn), (gen_inn12(S, f"b{i}"), valid_inn),
                        (gen_ogrn(S, f"c{i}"), valid_ogrn)):
            got, _ = TS.sanitize_text(f"реквизит {src}")
            assert src not in got, src
            assert ok(normalize_digits(got.split(" ", 1)[1]))

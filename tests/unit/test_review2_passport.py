# Паспорт в свободном тексте (ревью 2, Н3): один идентификатор - одна замена.
# Ключ идентичности - 10 цифр series‖number через ОДНУ gen_digits_like,
# тот же ключ, что у структурной пары колонок (cmd_transformer._passport_pair)
# и у doc_number. До правки текст покрывался только формой «4 цифры + ровно
# один пробел + 6», а «4509-123456» и «серия ... номер ...» уезжали как есть.
from pathlib import Path

from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import Mapper, Salt, gen_digits_like, normalize_digits
from sanitizer.postproc import TextSanitizer

SALT = Salt(b"review2", "dev", "g1")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))
TS = TextSanitizer(Mapper(SALT, CORPORA), SALT, frozenset(CORPORA["name_m"]))

EXPECTED = gen_digits_like(SALT, "4501123456")          # канонические 10 цифр


def test_passport_every_notation_one_replacement():
    """Один паспорт в четырёх написаниях -> одни и те же 10 цифр замены,
    разделители исходника сохранены. Property-тест класса «N представлений ->
    одна замена», обязательный для новых типов (ревью 2, §6.14 п.2)."""
    for text in ("паспорт 4501 123456", "паспорт 4501  123456",
                 "паспорт 4509-123456".replace("4509", "4501"),
                 "серия 4501, номер 123456", "серия 4501 номер 123456"):
        out, _ = TS.sanitize_text(text)
        assert "4501" not in out and "123456" not in out, text
        assert normalize_digits(out) == EXPECTED, text


def test_passport_replacement_keeps_source_separators():
    out, _ = TS.sanitize_text("паспорт 4501-123456")
    assert f"{EXPECTED[:4]}-{EXPECTED[4:]}" in out
    out, _ = TS.sanitize_text("серия 4501, номер 123456")
    assert f"серия {EXPECTED[:4]}, номер {EXPECTED[4:]}" in out


def test_bare_ten_digits_without_checksum_stay_untouched():
    """Голые 10 цифр подряд - конфликт с ИНН-10, там решает контрольная
    сумма (_checksummed), а не формат. Число без валидной КС не трогается."""
    out, _ = TS.sanitize_text("заявка 4501123456 принята")
    assert "4501123456" in out

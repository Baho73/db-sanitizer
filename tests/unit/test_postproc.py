# Тесты M-POSTPROC без дампа: текстовый санитайзер - канарейки, страховочный
# слой, консистентность с mapper, кэш LLM. (T-010)
from pathlib import Path

from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import Mapper, Salt
from sanitizer.postproc import TextSanitizer

SALT = Salt(b"m", "dev", "g1")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))
NAMES = frozenset(CORPORA["name_m"] + CORPORA["name_f"] +
                  CORPORA["patronymic_m"] + CORPORA["patronymic_f"] +
                  ["тестослав", "проверочич", "марью", "канареевну"])


def make_ts(llm=None):
    return TextSanitizer(Mapper(SALT, CORPORA), SALT, NAMES, llm=llm)


def test_regex_shield_catches_formats():
    ts = make_ts()
    out, _ = ts.sanitize_text("тел 8-999-777-00-02, почта ivan@corp.ru, СНИЛС 123-456-789 64")
    # Утверждения раздельные и безусловные: дизъюнкция «A или B» оставалась
    # зелёной при ослабленном поведении - достаточно было выполнить B.
    assert "8-999-777-00-02" not in out
    assert "+7" in out                       # телефон заменён, а не вырезан
    assert "ivan@corp.ru" not in out and "@" in out
    assert "123-456-789 64" not in out


def test_fio_initials_replaced_consistently():
    ts = make_ts()
    out, _ = ts.sanitize_text("Согласовал Канарейкина В.П., вопросы к ней")
    assert "Канарейкина" not in out
    # фамильный компонент совпадает с заменой полной формы (критерий §7)
    full_fam = Mapper(SALT, CORPORA).fio("Канарейкина", "Вера", "Петровна")[0]
    assert full_fam.capitalize() in out


def test_full_fio_replaced():
    ts = make_ts()
    out, _ = ts.sanitize_text("Обращение от Канарейкин Тестослав Проверович, срочно")
    assert "Канарейкин" not in out and "Тестослав" not in out


def test_plain_words_untouched():
    ts = make_ts()
    src = "Плановое обслуживание станка Механизм Устройство"
    out, _ = ts.sanitize_text(src)
    assert out == src                                       # не-ФИО заглавные пары не тронуты


def test_confident_patronymic_needs_no_llm():
    ts = make_ts(llm=None)
    out, notes = ts.sanitize_text("спросить Марью Ивановну на проходной")
    assert "Ивановну" not in out and notes == []            # отчество - сильный якорь


def test_ambiguous_fragment_uses_llm_cache():
    calls = []

    def llm(fragment):
        calls.append(fragment)
        return True

    ts = make_ts(llm=llm)
    # «Хтонираду» не в словаре и без якорных суффиксов, «Иванову» - фамильный якорь
    out1, n1 = ts.sanitize_text("передать Хтонираду Иванову документы")
    out2, _ = ts.sanitize_text("передать Хтонираду Иванову документы")
    assert "Иванову" not in out1
    assert len(calls) == 1                                  # второй раз - из кэша
    assert n1 == []


def test_no_llm_marks_degradation():
    ts = make_ts(llm=None)
    out, notes = ts.sanitize_text("передать Зюкозавру Хтоническому пакет")
    # Слово с фамильным суффиксом, но не из словаря; модели нет -> фрагмент
    # остаётся неизменным И помечается деградацией. Оба условия обязательны:
    # «пометка ИЛИ неизменность» проходила при любом из двух исходов.
    assert notes == ["low_confidence_ner"]
    assert out == "передать Зюкозавру Хтоническому пакет"


def test_address_column_replaced_whole():
    """Адресная колонка: от исходной строки не остаётся НИЧЕГО - ни улицы,
    ни квартиры, ни кода домофона (§3.2, регресс найден на живом стенде)."""
    ts = make_ts()
    ts.aggressive = True
    src = "мск, тверскя 5 кв 12, спросить Марью Канареевну, домофон 7701"
    out, _ = ts.sanitize_text(src)
    for leak in ("тверскя", "кв 12", "7701", "Канареевну", "мск"):
        assert leak not in out, leak
    assert out.startswith(tuple(r.title() for r in CORPORA["region"]))
    assert ts.sanitize_text(src)[0] == out          # детерминизм


def test_address_same_input_same_output():
    ts = make_ts()
    ts.aggressive = True
    a, _ = ts.sanitize_text("г. Видное, пр. Фестивальный 81 кв 159")
    b, _ = ts.sanitize_text("Г. ВИДНОЕ,  пр. Фестивальный 81 кв 159")
    assert a == b                                    # ключ - нормализованная строка


def test_snils_canary_from_demo():
    ts = make_ts()
    out, _ = ts.sanitize_text("Сверьте СНИЛС 123-456-789 64 в личном деле.")
    assert "123-456-789 64" not in out and "СНИЛС" in out

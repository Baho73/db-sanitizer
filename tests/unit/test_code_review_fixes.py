# Тесты находок внешнего ревью docs/code-review-2026-07-31.md. Каждый красный
# на коде до правки. (T-108)
import re
from pathlib import Path

import pytest

from sanitizer.classifier import ClassifiedColumn, SemType
from sanitizer.cmd_transformer import RowTransformer
from sanitizer.corpus import build_corpora, load_components
from sanitizer.mapper import (
    Salt, gen_int_like, gen_luhn_like, gen_snils, luhn_ok, normalize_digits, valid_snils,
)
from sanitizer.policy import Plan, PlanColumn, assign, validate_plan
from sanitizer.postproc import TextSanitizer
from sanitizer.profiler import ColumnInfo, Snapshot

S = Salt(b"t", "d", "g")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))


def _plan(**cols) -> Plan:
    return Plan(1, "f", {f"hr.t.{k}": v for k, v in cols.items()}, [], [], {}, {"hr.t": ["id"]})


def _t(tmp_path, **cols) -> RowTransformer:
    return RowTransformer(_plan(**cols), "hr.t", S, CORPORA, tmp_path)


def _ts(tmp_path) -> TextSanitizer:
    return TextSanitizer(_t(tmp_path).mapper, S, frozenset())


# --- блокер: одно значение в разных написаниях -> одна замена ---

@pytest.mark.parametrize("shape", ["{}", "{0:.3}-{0:.6}-{0}"])
def test_snils_same_replacement_in_every_notation(tmp_path, shape):
    """Двойная трансформация: дефисная запись заменялась, результат тут же
    попадал под шаблон идентификатора и заменялся второй раз."""
    ts = _ts(tmp_path)
    flat = gen_snils(S, "victim")
    dashed = f"{flat[:3]}-{flat[3:6]}-{flat[6:9]} {flat[9:]}"
    spaced = f"{flat[:3]} {flat[3:6]} {flat[6:9]} {flat[9:]}"
    got = {normalize_digits(ts.sanitize_text(f"СНИЛС {form}")[0])
           for form in (flat, dashed, spaced)}
    assert len(got) == 1, got
    assert got == {normalize_digits(gen_snils(S, flat))}   # совпадает с колонкой


def test_separators_of_source_are_preserved(tmp_path):
    flat = gen_snils(S, "sep")
    dashed = f"{flat[:3]}-{flat[3:6]}-{flat[6:9]} {flat[9:]}"
    out, _ = _ts(tmp_path).sanitize_text(dashed)
    assert re.fullmatch(r"\d{3}-\d{3}-\d{3} \d{2}", out), out


# --- страховочный слой: пробелы, телефон без плюса, кириллица, карты ---

def test_phone_without_plus_is_replaced(tmp_path):
    out, _ = _ts(tmp_path).sanitize_text("тел 7 905 123-45-67")
    assert "905 123-45-67" not in out and "+7" in out


def test_cyrillic_email_domain_is_replaced(tmp_path):
    out, _ = _ts(tmp_path).sanitize_text("почта ivan@домен.рф")
    assert "ivan@домен.рф" not in out and "@" in out


def test_card_number_replaced_and_stays_valid(tmp_path):
    card = "4276380012345670"
    while not luhn_ok(card):
        card = str(int(card) + 1)
    out, _ = _ts(tmp_path).sanitize_text(f"оплата картой {card}")
    new = re.search(r"\d{16}", out).group()
    assert new != card and luhn_ok(new)


def test_number_without_checksum_untouched(tmp_path):
    text = "заявка 1234567890 от 20 05 2026, инвентарный 000000000001"
    assert _ts(tmp_path).sanitize_text(text)[0] == text


# --- fail-open через неизвестные значения в плане ---

def test_unknown_strategy_rejected_by_validation():
    snap = Snapshot([ColumnInfo("hr.t", "x", "character varying", 20, True, False,
                                False, 10, 0.0, ["a"])], [], {})
    plan = Plan(1, "f", {"hr.t.x": PlanColumn("family", "fkae", "corpus", "typo")},
                [], [], {}, {})
    errors = validate_plan(plan, snap)
    assert any("неизвестная стратегия" in e for e in errors)


def test_unknown_strategy_stops_transformer(tmp_path):
    t = _t(tmp_path, x=PlanColumn("family", "fkae", "corpus", "typo"))
    with pytest.raises(ValueError, match="неизвестная стратегия"):
        t.transform_row({"x": {"d": "Иванов", "n": False}})


def test_generalize_of_unsupported_type_stops(tmp_path):
    t = _t(tmp_path, x=PlanColumn("salary", "generalize", "none", "x"))
    with pytest.raises(ValueError, match="generalize"):
        t.transform_row({"x": {"d": "100000", "n": False}})


# --- email больше не уезжает в корпус названий организаций ---

def test_email_stays_email_even_without_unique(tmp_path):
    col = ColumnInfo("hr.t", "email", "character varying", 120, True, False, False,
                     50, 0.0, ["a@b.ru"])
    plan = assign([ClassifiedColumn("hr.t.email", SemType.EMAIL, 0.9, False, "agree")],
                  Snapshot([col], [], {"hr.t": 50}))
    assert plan.columns["hr.t.email"].strategy == "generate"
    t = _t(tmp_path, email=PlanColumn("email", "fake", "corpus", "принудительно"))
    out = t.transform_row({"email": {"d": "ivan.petrov@mail.ru", "n": False}})["email"]["d"]
    assert "@" in out and out != "ivan.petrov@mail.ru"


# --- целое с ведущим нулём: инъективность не гарантируется, значит отказ ---

def test_leading_zero_integer_is_refused():
    with pytest.raises(ValueError, match="ведущим нулём"):
        gen_int_like(S, "012345")
    assert gen_int_like(S, "112345") > 0        # обычный вход работает


def test_luhn_generator_is_injective():
    cards = [c for c in (str(4276380012345670 + i) for i in range(300)) if luhn_ok(c)]
    outs = {gen_luhn_like(S, c) for c in cards}
    assert len(outs) == len(cards) and all(luhn_ok(o) for o in outs)


def test_snils_replacement_keeps_checksum(tmp_path):
    out, _ = _ts(tmp_path).sanitize_text(gen_snils(S, "x"))
    assert valid_snils(normalize_digits(out))

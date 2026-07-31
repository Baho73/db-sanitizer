# Тесты порчи данных (ранг 3 разбора 4). Каждый воспроизводит дефект, который
# демо-база скрывала отсутствием ломающего случая. (T-106)
import json
from pathlib import Path

import pytest

from sanitizer.corpus import build_corpora, load_components
from sanitizer.cmd_transformer import RowTransformer
from sanitizer.mapper import (
    Salt, gen_digits_like, gen_int_like, pick_int, valid_inn, valid_snils,
)
from sanitizer.policy import Plan, PlanColumn
from sanitizer.postproc import TextSanitizer, _copy_escape, _copy_unescape

S = Salt(b"t", "d", "g")
CORPORA = build_corpora(load_components(Path("sanitizer/data/components-ru.json")))


def _plan(**cols) -> Plan:
    return Plan(1, "f", {f"hr.t.{k}": v for k, v in cols.items()}, [], [], {})


def _t(tmp_path, **cols) -> RowTransformer:
    return RowTransformer(_plan(**cols), "hr.t", S, CORPORA, tmp_path)


# --- находка 5: контрольная сумма 10-значного ИНН ---

def test_inn10_keeps_valid_checksum(tmp_path):
    t = _t(tmp_path, inn=PlanColumn("inn", "generate", "none", "x"))
    for src in ("7707083893", "7736050003", "5024002119"):
        assert valid_inn(src), "исходник должен быть валиден"
        out = t.transform_row({"inn": {"d": src, "n": False}})["inn"]["d"]
        assert out != src and valid_inn(out), f"{src} -> {out}"


def test_inn12_still_valid(tmp_path):
    t = _t(tmp_path, inn=PlanColumn("inn", "generate", "none", "x"))
    out = t.transform_row({"inn": {"d": "500100732259", "n": False}})["inn"]["d"]
    assert len(out) == 12 and valid_inn(out)


# --- находка 6: коллизия целых вне окна ---

def test_int_like_no_collision_across_widths():
    assert gen_int_like(S, "100001") != gen_int_like(S, "1000001")


def test_int_like_preserves_width_and_is_injective():
    srcs = [str(100000 + i) for i in range(2000)] + [str(1000000 + i) for i in range(200)]
    outs = [gen_int_like(S, s) for s in srcs]
    assert len(set(outs)) == len(srcs)                       # инъективность
    assert all(len(str(o)) == len(s) for o, s in zip(outs, srcs))   # разрядность


def test_pick_int_is_honest_about_range():
    vals = {pick_int(S, f"k{i}", 1, 99) for i in range(500)}
    assert vals and max(vals) <= 99 and min(vals) >= 1


# --- находка 7: обратный слэш в тексте ---

@pytest.mark.parametrize("original", [
    "a\\tb", "c\rd", "e\\\\f", "g\th", "путь C:\\shared\\акт.pdf", "перенос\nстрока",
])
def test_copy_escaping_round_trip(original):
    assert _copy_unescape(_copy_escape(original)) == original


# --- находка 9: NULL остаётся NULL ---

def test_null_middle_name_stays_null(tmp_path):
    t = _t(tmp_path,
           last_name=PlanColumn("family", "fake", "corpus", "x"),
           first_name=PlanColumn("name", "fake", "corpus", "x"),
           middle_name=PlanColumn("patronymic", "fake", "corpus", "x"))
    out = t.transform_row({
        "last_name": {"d": "Иванов", "n": False},
        "first_name": {"d": "Пётр", "n": False},
        "middle_name": {"d": None, "n": True},
    })
    assert out["middle_name"] == {"d": None, "n": True}
    assert out["last_name"]["d"] != "Иванов"


# --- сквозная консистентность: один адрес - одна замена в обоих проходах ---

def test_address_same_in_column_and_in_text(tmp_path):
    raw = "Тверская область, г. Ржев, ул. Садовая, д. 5"
    t = _t(tmp_path, addr=PlanColumn("address", "fake", "corpus", "x"))
    from_column = t.transform_row({"addr": {"d": raw, "n": False}})["addr"]["d"]
    ts = TextSanitizer(t.mapper, S, frozenset())
    from_text, _ = ts.sanitize_text(raw, aggressive=True)
    assert from_column == from_text


def test_inn_same_in_column_and_in_text(tmp_path):
    src = "7707083893"
    t = _t(tmp_path, inn=PlanColumn("inn", "generate", "none", "x"))
    from_column = t.transform_row({"inn": {"d": src, "n": False}})["inn"]["d"]
    ts = TextSanitizer(t.mapper, S, frozenset())
    from_text, _ = ts.sanitize_text(f"договор с ИНН {src} подписан")
    assert from_column in from_text


# --- размеченный ключ jsonb обрабатывается, а не обнуляется ---

def test_jsonb_snils_is_replaced_not_blanked(tmp_path):
    t = _t(tmp_path, attrs=PlanColumn("free_text", "jsonb", "none", "x",
                                      json_fields={"snils": "snils", "note": "keep"}))
    src = {"snils": "112-233-445 95", "note": "ok"}
    got = json.loads(t.transform_row(
        {"attrs": {"d": json.dumps(src, ensure_ascii=False), "n": False}})["attrs"]["d"])
    assert got["note"] == "ok"
    assert got["snils"] != src["snils"] and valid_snils(got["snils"].replace("-", "").replace(" ", ""))


# --- паспорт стал инъективным ---

def test_passport_generation_is_injective():
    outs = {gen_digits_like(S, f"45{i:02d} {j:06d}") for i in range(10) for j in range(100)}
    assert len(outs) == 1000

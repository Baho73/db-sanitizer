# Интеграционный тест M-CLASSIFIER против демо-базы. Закрывает критерий §7
# «полнота классификации чувствительных колонок»: измеряет recall/precision
# на размеченном наборе, а не декларирует их. (T-005)
import json
import os
from pathlib import Path

import pytest

DSN = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")

try:
    import psycopg
    with psycopg.connect(DSN, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="demo-db not running")

from sanitizer.classifier import PII_TYPES, SemType, classify, llm_classify  # noqa: E402
from sanitizer.profiler import profile  # noqa: E402

# Эталонная разметка: какие колонки демо-базы содержат ПДн. Ведётся вручную -
# это и есть «размеченный набор» из §7. Оговорка: демо-база даёт 69 колонок,
# критерий просит >=200 - на реальной базе набор должен быть шире.
SENSITIVE = {
    "hr.employees.last_name", "hr.employees.first_name", "hr.employees.middle_name",
    "hr.employees.birth_date", "hr.employees.inn", "hr.employees.snils",
    "hr.employees.passport_series", "hr.employees.passport_number",
    "hr.employees.phone", "hr.employees.email", "hr.employees.salary",
    "hr.employees.attrs", "hr.employees.tab_no",
    "hr.addresses.addr_text", "hr.documents.doc_number",
    "hr.contractors.inn", "hr.contractors.ogrn", "hr.contractors.city",
    "hr.contracts.contractor_inn", "hr.payroll.amount",
    "hr.tickets.body_text", "hr.tickets.subject", "hr.ticket_comments.comment_text",
}


@pytest.fixture(scope="module")
def classified():
    snap = profile(DSN, "hr")
    votes = llm_classify(snap.columns, Path("tests/fixtures/llm_votes_demo.json"))
    return snap, {c.column: c for c in classify(snap.columns, votes)}


def test_recall_precision_meet_acceptance(classified):
    """§7: recall >= 0.98 по чувствительным, precision >= 0.85."""
    _, res = classified
    detected = {name for name, c in res.items()
                if c.sem_type in PII_TYPES or c.unresolved}
    tp = len(SENSITIVE & detected)
    fn = SENSITIVE - detected
    fp = detected - SENSITIVE
    recall = tp / len(SENSITIVE)
    precision = tp / len(detected) if detected else 0.0
    print(f"\nразмечено чувствительных: {len(SENSITIVE)}, колонок всего: {len(res)}")
    print(f"recall={recall:.3f} precision={precision:.3f}")
    print(f"пропущены: {sorted(fn) or 'нет'}")
    print(f"ложные срабатывания: {sorted(fp) or 'нет'}")
    assert recall >= 0.98, f"пропущены ПДн-колонки: {sorted(fn)}"
    assert precision >= 0.85, f"слишком много ложных: {sorted(fp)}"


def test_uninformative_column_goes_unresolved(classified):
    """f_115 не распознаётся ни одним голосом - должна уйти человеку, не в keep."""
    _, res = classified
    c = res["hr.employees.f_115"]
    assert c.unresolved or c.sem_type is None, c


def test_checksum_types_detected_without_llm(classified):
    """ИНН/СНИЛС/ОГРН распознаются правилами по контрольной сумме."""
    _, res = classified
    for col, expect in (("hr.employees.inn", SemType.INN),
                        ("hr.employees.snils", SemType.SNILS),
                        ("hr.contractors.ogrn", SemType.OGRN)):
        assert res[col].sem_type == expect, (col, res[col])


def test_lying_column_name_still_flagged(classified):
    """hr.contractors.city содержит полные адреса - имя колонки врёт."""
    _, res = classified
    c = res["hr.contractors.city"]
    assert c.sem_type in (SemType.CITY, SemType.ADDRESS) or c.unresolved


def test_metrics_are_reported_to_file(classified, tmp_path):
    """Метрики - артефакт прогона, а не только вывод в консоль."""
    _, res = classified
    detected = {n for n, c in res.items() if c.sem_type in PII_TYPES or c.unresolved}
    report = {"labelled": len(SENSITIVE), "columns": len(res),
              "recall": len(SENSITIVE & detected) / len(SENSITIVE),
              "precision": len(SENSITIVE & detected) / len(detected)}
    p = tmp_path / "classifier-metrics.json"
    p.write_text(json.dumps(report, indent=1), encoding="utf-8")
    assert json.loads(p.read_text(encoding="utf-8"))["recall"] >= 0.98

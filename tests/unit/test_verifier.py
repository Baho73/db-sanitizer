# Юнит-тесты M-VERIFIER: энтропия, отчёт. Полные проверки - в e2e. (T-011)
from sanitizer.verifier import Check, VerifyReport, entropy, render_markdown


def test_entropy():
    assert entropy([50, 50]) == 1.0
    assert entropy([100]) == 0.0
    assert entropy([]) == 0.0
    assert entropy([1] * 1024) == 10.0


def test_report_gate():
    r = VerifyReport()
    r.add("a", True, "ok")
    assert r.ok
    r.add("b", False, "утечка")
    assert not r.ok
    md = render_markdown(r)
    assert "✅" in md and "❌" in md and "утечка" in md

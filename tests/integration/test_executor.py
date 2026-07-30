# Интеграционный тест M-EXECUTOR: подготовка артефактов против живой БД и
# реальный запуск greenmask dump. (T-009)
import json
import os
import shutil
from pathlib import Path

import pytest

DSN = os.environ.get("DEMO_DSN", "postgresql://demo:demo@127.0.0.1:55432/demo")
GREENMASK = os.environ.get("GREENMASK_BIN", "greenmask")

try:
    import psycopg
    with psycopg.connect(DSN, connect_timeout=3):
        DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(
    not DB_UP or not shutil.which(GREENMASK),
    reason="нужны demo-db и бинарь greenmask (запускать в tool-контейнере)")

from sanitizer.corpus import build_corpora, load_components  # noqa: E402
from sanitizer.executor import greenmask_config, prepare_artifacts, run_pass1  # noqa: E402
from sanitizer.mapper import Salt  # noqa: E402
from sanitizer.policy import Plan  # noqa: E402
from sanitizer.runlog import RunLog  # noqa: E402

PLAN = Path("out/sanitization-plan.yaml")
SALT = Salt(b"integration-master", "test", "g1")


@pytest.fixture(scope="module")
def plan():
    if not PLAN.exists():
        pytest.skip("нет плана прогона")
    return Plan.load(PLAN)


@pytest.fixture(scope="module")
def corpora():
    return build_corpora(load_components(Path("sanitizer/data/components-ru.json")))


def test_artifacts_are_injective(plan, corpora, tmp_path):
    """direct-отображение 1:1 обязано быть инъективным - иначе схлопнется
    энтропия и упадёт UNIQUE."""
    written = prepare_artifacts(plan, DSN, SALT, corpora, tmp_path / "art")
    assert written
    for p in written:
        m = json.loads(p.read_text(encoding="utf-8"))
        if p.name.startswith("direct."):
            assert len(set(m.values())) == len(m), f"коллизии в {p.name}"
            assert all(k != v for k, v in m.items()), f"тождественная замена в {p.name}"


def test_shuffle_map_is_permutation(plan, corpora, tmp_path):
    """shuffle - перестановка: мультимножество значений не меняется."""
    written = prepare_artifacts(plan, DSN, SALT, corpora, tmp_path / "art")
    shuffles = [p for p in written if p.name.startswith("shuffle.")]
    assert shuffles, "в плане нет shuffle-колонок"
    for p in shuffles:
        m = json.loads(p.read_text(encoding="utf-8"))
        # имя вида shuffle.<схема>.<таблица>.<колонка>
        _, schema, tbl, col = p.stem.split(".")
        table = f"{schema}.{tbl}"
        with psycopg.connect(DSN) as conn:
            src = [str(r[0]) for r in conn.execute(f"SELECT {col}::text FROM {table}")]
        assert sorted(m.values()) == sorted(src)


def test_artifacts_are_deterministic(plan, corpora, tmp_path):
    a = prepare_artifacts(plan, DSN, SALT, corpora, tmp_path / "a")
    b = prepare_artifacts(plan, DSN, SALT, corpora, tmp_path / "b")
    for pa, pb in zip(sorted(a), sorted(b)):
        assert pa.read_text(encoding="utf-8") == pb.read_text(encoding="utf-8"), pa.name


def test_config_routes_equivalence_classes_through_cmd(plan, tmp_path):
    """Правило единого движка §5.1: классы эквивалентности - только через Cmd."""
    cfg = greenmask_config(plan, DSN, tmp_path / "d", PLAN, tmp_path / "art")
    routed = {}
    for tr in cfg["dump"]["transformation"]:
        table = f'{tr["schema"]}.{tr["name"]}'
        for t in tr["transformers"]:
            for c in t["params"]["columns"]:
                routed[f'{table}.{c["name"]}'] = t["name"]
    for cls in plan.classes:
        for col in cls:
            if col in plan.columns and plan.columns[col].strategy not in ("keep", "unresolved"):
                assert routed.get(col) == "Cmd", f"{col} не через Cmd"


def test_freetext_columns_absent_from_pass1(plan, tmp_path):
    cfg = greenmask_config(plan, DSN, tmp_path / "d", PLAN, tmp_path / "art")
    named = {f'{tr["schema"]}.{tr["name"]}.{c["name"]}'
             for tr in cfg["dump"]["transformation"]
             for t in tr["transformers"] for c in t["params"]["columns"]}
    for col, pc in plan.columns.items():
        if pc.strategy == "freetext":
            assert col not in named, f"{col} не должна обрабатываться в проходе 1"


def test_run_pass1_produces_restorable_dump(plan, corpora, tmp_path):
    """Живой прогон greenmask: на выходе валидный directory-дамп."""
    rl = RunLog(tmp_path / "rl.db")
    run_id = rl.start_run(plan.schema_fingerprint, "test", "g1")
    dump = run_pass1(plan, DSN, SALT, corpora, tmp_path, rl, run_id,
                     greenmask_bin=GREENMASK, plan_path=PLAN)
    assert (dump / "toc.dat").exists()
    assert list(dump.glob("*.dat.gz"))
    stages = {(s, st) for s, _, st, _ in rl.entries(run_id)}
    assert ("pass1", "done") in stages
    assert not rl.publishable(run_id)      # без verify публикация запрещена

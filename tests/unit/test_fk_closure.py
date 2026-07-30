# Тесты M-FK-CLOSURE: классы по FK (композитные поколоночно), мягкие связи. (T-006)
from sanitizer.fk_closure import equivalence_classes, soft_links
from sanitizer.profiler import ColumnInfo, ForeignKey, Snapshot


def snap(fks, columns=()):
    return Snapshot(list(columns), fks, {})


def test_simple_fk_class():
    s = snap([ForeignKey("hr.a", ("dept_id",), "hr.d", ("id",))])
    [cls] = equivalence_classes(s)
    assert cls == {"hr.a.dept_id", "hr.d.id"}


def test_composite_fk_pairs_by_position():
    s = snap([ForeignKey("hr.ship", ("contract_id", "item_no"), "hr.items", ("contract_id", "item_no"))])
    classes = equivalence_classes(s)
    assert {"hr.ship.contract_id", "hr.items.contract_id"} in classes
    assert {"hr.ship.item_no", "hr.items.item_no"} in classes
    # позиции НЕ перемешаны в один класс
    assert not any("hr.ship.contract_id" in c and "hr.items.item_no" in c for c in classes)


def test_transitive_closure_and_extra_links():
    s = snap([ForeignKey("hr.b", ("x",), "hr.a", ("id",)),
              ForeignKey("hr.c", ("y",), "hr.b", ("x",))])
    [cls] = equivalence_classes(s, extra_links=[("hr.a.id", "hr.d.z")])
    assert cls == {"hr.a.id", "hr.b.x", "hr.c.y", "hr.d.z"}


def test_soft_link_detects_inn_containment():
    inns = [f"77{i:010d}" for i in range(30)]
    a = ColumnInfo("hr.contracts", "contractor_inn", "character varying", 12, False, False, False,
                   30, 0.0, inns[:25])
    b = ColumnInfo("hr.contractors", "inn", "character varying", 12, False, False, False,
                   30, 0.0, inns)
    c = ColumnInfo("hr.employees", "email", "character varying", 120, False, True, False,
                   30, 0.0, [f"u{i}@x.ru" for i in range(30)])
    links = soft_links(snap([], [a, b, c]))
    assert any({x[0], x[1]} == {"hr.contracts.contractor_inn", "hr.contractors.inn"} for x in links)
    assert not any("email" in x[0] or "email" in x[1] for x in links)

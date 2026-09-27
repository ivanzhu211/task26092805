"""条件三值逻辑：布尔与数字、子条件乱序、组合语义。"""
from datetime import datetime, timezone

from policy_engine.conditions import evaluate_condition
from policy_engine.models import (
    AllOf,
    AnyOf,
    AttrCompare,
    IpInNetworks,
    LeafTrace,
    Not,
    TimeRange,
    TriState,
)

M = datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc)
ATTRS = {"dept": "sales", "level": 5, "vip": True, "ratio": 0.5}


def ev(cond, attrs=ATTRS, ip=None):
    return evaluate_condition(cond, attrs, ip, M, "UTC")


def test_bool_is_not_number():
    assert ev(AttrCompare("vip", "eq", True)) is TriState.TRUE
    assert ev(AttrCompare("vip", "eq", 1)) is TriState.UNKNOWN
    assert ev(AttrCompare("level", "eq", True)) is TriState.UNKNOWN
    assert ev(AttrCompare("vip", "gt", False)) is TriState.UNKNOWN  # 布尔无大小比较


def test_number_comparisons():
    assert ev(AttrCompare("level", "gt", 3)) is TriState.TRUE
    assert ev(AttrCompare("level", "lt", 3)) is TriState.FALSE
    assert ev(AttrCompare("ratio", "eq", 0.5)) is TriState.TRUE
    assert ev(AttrCompare("level", "in", [4, 5, 6])) is TriState.TRUE
    assert ev(AttrCompare("level", "in", [1, 2])) is TriState.FALSE
    assert ev(AttrCompare("level", "in", ["a", "b"])) is TriState.UNKNOWN


def test_missing_attr_and_type_mismatch_unknown():
    assert ev(AttrCompare("nope", "eq", 1)) is TriState.UNKNOWN
    assert ev(AttrCompare("dept", "gt", 3)) is TriState.UNKNOWN


def test_all_any_not_tri_state():
    t = AttrCompare("dept", "eq", "sales")
    f = AttrCompare("dept", "eq", "other")
    u = AttrCompare("nope", "eq", 1)
    assert ev(AllOf((t, u))) is TriState.UNKNOWN
    assert ev(AllOf((f, u))) is TriState.FALSE
    assert ev(AllOf((t, t))) is TriState.TRUE
    assert ev(AnyOf((f, u))) is TriState.UNKNOWN
    assert ev(AnyOf((t, u))) is TriState.TRUE
    assert ev(AnyOf((f, f))) is TriState.FALSE
    assert ev(Not(u)) is TriState.UNKNOWN
    assert ev(Not(t)) is TriState.FALSE
    assert ev(Not(f)) is TriState.TRUE


def test_result_independent_of_child_order():
    children = [
        AttrCompare("dept", "eq", "sales"),
        AttrCompare("nope", "eq", 1),
        AttrCompare("level", "gt", 3),
        Not(AttrCompare("vip", "eq", False)),
    ]
    import itertools

    results = set()
    trace_results = set()
    for perm in itertools.permutations(children):
        traces = []
        r = evaluate_condition(AllOf(perm), ATTRS, None, M, "UTC", traces)
        results.add(r)
        trace_results.add(tuple((t.description, t.result) for t in traces))
    assert results == {TriState.UNKNOWN}
    assert len(trace_results) == 1  # 叶子记录顺序也稳定


def test_ip_leaf_unknown_on_bad_ip():
    cond = IpInNetworks(("10.0.0.0/8",))
    assert ev(cond, ip="10.1.1.1") is TriState.TRUE
    assert ev(cond, ip="bad") is TriState.UNKNOWN
    assert ev(cond, ip=None) is TriState.UNKNOWN


def test_time_leaf_trace_recorded():
    traces = []
    evaluate_condition(TimeRange("09:00", "18:00"), ATTRS, None, M, "UTC", traces)
    assert len(traces) == 1
    assert traces[0].result is TriState.TRUE
    assert isinstance(traces[0], LeafTrace)

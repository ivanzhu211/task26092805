"""Leaf and combinator semantics: time ranges, DST, IP, types, ordering."""
import itertools
from datetime import datetime, timezone

import pytest

from policy_engine.conditions import evaluate_condition, validate_condition
from policy_engine.types import (
    All, AnyOf, AttrCompare, IPInNetworks, Not, TimeRange, Tri,
)


def ev(cond, attrs=None, ip=None, hhmm=None):
    return evaluate_condition(cond, attrs or {}, ip, hhmm)[0]


# ---------- time ranges ----------

@pytest.mark.parametrize("hhmm,expected", [
    ("22:00", Tri.TRUE),   # start inclusive
    ("23:59", Tri.TRUE),
    ("00:00", Tri.TRUE),   # after midnight, still inside
    ("05:59", Tri.TRUE),
    ("06:00", Tri.FALSE),  # end exclusive
    ("21:59", Tri.FALSE),
    ("12:00", Tri.FALSE),
])
def test_cross_midnight(hhmm, expected):
    assert ev(TimeRange("22:00", "06:00"), hhmm=hhmm) is expected


def test_same_start_end_rejected():
    with pytest.raises(ValueError):
        validate_condition(TimeRange("08:00", "08:00"))


def test_bad_time_format_rejected():
    with pytest.raises(ValueError):
        validate_condition(TimeRange("25:00", "26:00"))


# ---------- leaves: attribute comparison ----------

def test_bool_is_not_a_number():
    # True must not compare equal to 1
    assert ev(AttrCompare("x", "eq", 1), {"x": True}) is Tri.UNKNOWN
    assert ev(AttrCompare("x", "eq", True), {"x": 1}) is Tri.UNKNOWN
    assert ev(AttrCompare("x", "eq", True), {"x": True}) is Tri.TRUE
    assert ev(AttrCompare("x", "gt", 0), {"x": True}) is Tri.UNKNOWN


def test_numeric_and_string_compare():
    assert ev(AttrCompare("n", "gt", 3), {"n": 4}) is Tri.TRUE
    assert ev(AttrCompare("n", "lt", 3), {"n": 4}) is Tri.FALSE
    assert ev(AttrCompare("s", "lt", "b"), {"s": "a"}) is Tri.TRUE
    assert ev(AttrCompare("s", "ne", "a"), {"s": "a"}) is Tri.FALSE
    assert ev(AttrCompare("n", "in", [1, 2]), {"n": 2}) is Tri.TRUE
    assert ev(AttrCompare("n", "in", [1, 2]), {"n": 3}) is Tri.FALSE
    # 'in' with no same-category element -> unknown
    assert ev(AttrCompare("n", "in", ["a", "b"]), {"n": 1}) is Tri.UNKNOWN


def test_missing_attr_and_type_mismatch_are_unknown():
    assert ev(AttrCompare("missing", "eq", 1), {}) is Tri.UNKNOWN
    assert ev(AttrCompare("x", "eq", "1"), {"x": 1}) is Tri.UNKNOWN
    assert ev(AttrCompare("x", "gt", "a"), {"x": 1}) is Tri.UNKNOWN


# ---------- leaves: IP networks ----------

def test_ipv4_mapped_ipv6_counts_as_ipv4():
    leaf = IPInNetworks(("10.0.0.0/8",))
    assert ev(leaf, ip="::ffff:10.1.2.3") is Tri.TRUE
    assert ev(leaf, ip="::ffff:11.0.0.1") is Tri.FALSE
    # mapped network notation normalizes to plain IPv4
    leaf2 = IPInNetworks(("::ffff:10.0.0.0/104",))
    assert ev(leaf2, ip="10.9.9.9") is Tri.TRUE
    assert ev(leaf2, ip="::ffff:10.9.9.9") is Tri.TRUE


def test_ipv6_networks():
    leaf = IPInNetworks(("2001:db8::/32",))
    assert ev(leaf, ip="2001:db8::1") is Tri.TRUE
    assert ev(leaf, ip="2001:db9::1") is Tri.FALSE


def test_invalid_ip_is_unknown():
    leaf = IPInNetworks(("10.0.0.0/8",))
    assert ev(leaf, ip="not-an-ip") is Tri.UNKNOWN
    assert ev(leaf, ip=None) is Tri.UNKNOWN


def test_host_bits_rejected():
    with pytest.raises(ValueError):
        validate_condition(IPInNetworks(("10.0.0.1/8",)))
    with pytest.raises(ValueError):
        validate_condition(IPInNetworks(("2001:db8::1/32",)))


# ---------- three-valued combinators, order independence ----------

def _leaf(attr, op, value):
    return AttrCompare(attr, op, value)


def test_all_any_not_truth_table():
    t = _leaf("a", "eq", 1)
    f = _leaf("a", "eq", 2)
    u = _leaf("b", "eq", 1)
    attrs = {"a": 1}
    assert ev(All((t, t)), attrs) is Tri.TRUE
    assert ev(All((t, u)), attrs) is Tri.UNKNOWN
    assert ev(All((f, u)), attrs) is Tri.FALSE
    assert ev(AnyOf((t, f)), attrs) is Tri.TRUE
    assert ev(AnyOf((f, u)), attrs) is Tri.UNKNOWN
    assert ev(AnyOf((f, f)), attrs) is Tri.FALSE
    assert ev(Not(t), attrs) is Tri.FALSE
    assert ev(Not(f), attrs) is Tri.TRUE
    assert ev(Not(u), attrs) is Tri.UNKNOWN


def test_result_independent_of_child_order():
    children = [
        AttrCompare("a", "eq", 1),      # TRUE
        AttrCompare("a", "eq", 2),      # FALSE
        AttrCompare("b", "eq", 1),      # UNKNOWN (missing)
        TimeRange("09:00", "18:00"),    # TRUE at 10:00
        IPInNetworks(("10.0.0.0/8",)),  # UNKNOWN (bad ip)
    ]
    attrs = {"a": 1}
    results_all, results_any = set(), set()
    for perm in itertools.permutations(children):
        results_all.add(ev(All(perm), attrs, ip="junk", hhmm="10:00"))
        results_any.add(ev(AnyOf(perm), attrs, ip="junk", hhmm="10:00"))
    assert results_all == {Tri.FALSE}
    assert results_any == {Tri.TRUE}

    # all-unknown mix: still order independent
    children2 = [AttrCompare("b", "eq", 1), IPInNetworks(("10.0.0.0/8",))]
    rs = {ev(All(p), {}, ip="junk") for p in itertools.permutations(children2)}
    assert rs == {Tri.UNKNOWN}

"""Condition tree evaluation (three-valued) and validation."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from .types import (
    All, AnyOf, AttrCompare, IPInNetworks, LeafTrace, Not, TimeRange, Tri,
)

_OPS = {"eq", "ne", "in", "gt", "lt"}
_HHMM = re.compile(r"^(\d{1,2}):([0-5]\d)$")


def _category(value: Any) -> str | None:
    """Attribute value category; bool is NOT a number."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return None


def _parse_hhmm(text: str) -> int:
    m = _HHMM.match(text)
    if not m:
        raise ValueError(f"invalid time of day: {text!r}")
    hh, mm = int(m.group(1)), int(m.group(2))
    if hh > 23:
        raise ValueError(f"invalid hour in {text!r}")
    return hh * 60 + mm


def _normalize_network(text: str):
    """Parse a CIDR; host bits set => ValueError. IPv4-mapped IPv6 nets
    are converted to plain IPv4 networks."""
    net = ipaddress.ip_network(text, strict=True)  # rejects host bits
    if net.version == 6 and net.prefixlen >= 96:
        mapped = net.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.ip_network(
                f"{mapped}/{net.prefixlen - 96}", strict=True
            )
    return net


def validate_condition(cond: Any) -> None:
    """Raise ValueError if the condition tree is invalid."""
    if isinstance(cond, AttrCompare):
        if cond.op not in _OPS:
            raise ValueError(f"unknown operator: {cond.op!r}")
        if cond.op == "in":
            if not isinstance(cond.value, (list, tuple)) or not cond.value:
                raise ValueError("'in' requires a non-empty list")
            for item in cond.value:
                if _category(item) is None:
                    raise ValueError(f"bad 'in' element: {item!r}")
        elif _category(cond.value) is None:
            raise ValueError(f"bad compare value: {cond.value!r}")
    elif isinstance(cond, TimeRange):
        if _parse_hhmm(cond.start) == _parse_hhmm(cond.end):
            raise ValueError("time range start must differ from end")
    elif isinstance(cond, IPInNetworks):
        if not cond.networks:
            raise ValueError("network list must not be empty")
        for net in cond.networks:
            _normalize_network(net)
    elif isinstance(cond, (All, AnyOf)):
        if not cond.children:
            raise ValueError("all/any requires at least one child")
        for child in cond.children:
            validate_condition(child)
    elif isinstance(cond, Not):
        validate_condition(cond.child)
    else:
        raise ValueError(f"unknown condition node: {cond!r}")


def _eval_attr(leaf: AttrCompare, attrs: dict[str, Any]) -> Tri:
    if leaf.attr not in attrs:
        return Tri.UNKNOWN
    actual = attrs[leaf.attr]
    cat = _category(actual)
    if cat is None:
        return Tri.UNKNOWN
    if leaf.op == "in":
        peers = [v for v in leaf.value if _category(v) == cat]
        if not peers:
            return Tri.UNKNOWN
        return Tri.TRUE if any(actual == v for v in peers) else Tri.FALSE
    expected = leaf.value
    if _category(expected) != cat:
        return Tri.UNKNOWN
    if leaf.op == "eq":
        return Tri.TRUE if actual == expected else Tri.FALSE
    if leaf.op == "ne":
        return Tri.TRUE if actual != expected else Tri.FALSE
    if cat == "bool":  # gt/lt on booleans: type mismatch
        return Tri.UNKNOWN
    try:
        if leaf.op == "gt":
            return Tri.TRUE if actual > expected else Tri.FALSE
        return Tri.TRUE if actual < expected else Tri.FALSE
    except TypeError:
        return Tri.UNKNOWN


def _eval_time_range(leaf: TimeRange, local_hhmm: str | None) -> Tri:
    if local_hhmm is None:
        return Tri.UNKNOWN
    t = _parse_hhmm(local_hhmm)
    start = _parse_hhmm(leaf.start)
    end = _parse_hhmm(leaf.end)
    if start < end:
        inside = start <= t < end
    else:  # crosses midnight
        inside = t >= start or t < end
    return Tri.TRUE if inside else Tri.FALSE


def _eval_ip(leaf: IPInNetworks, source_ip: str | None) -> Tri:
    if source_ip is None:
        return Tri.UNKNOWN
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return Tri.UNKNOWN
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # IPv4-mapped IPv6 counts as IPv4
    for net_text in leaf.networks:
        net = _normalize_network(net_text)
        if addr.version == net.version and addr in net:
            return Tri.TRUE
    return Tri.FALSE


def evaluate_condition(
    cond: Any,
    subject_attrs: dict[str, Any],
    source_ip: str | None,
    local_hhmm: str | None,
) -> tuple[Tri, list[LeafTrace]]:
    """Evaluate a condition tree. Returns (result, leaf traces).

    The fold is order-independent: all/any only count FALSE / UNKNOWN /
    TRUE outcomes, never short-circuit on position.
    """
    leaves: list[LeafTrace] = []

    def walk(node: Any) -> Tri:
        if isinstance(node, AttrCompare):
            r = _eval_attr(node, subject_attrs)
        elif isinstance(node, TimeRange):
            r = _eval_time_range(node, local_hhmm)
        elif isinstance(node, IPInNetworks):
            r = _eval_ip(node, source_ip)
        elif isinstance(node, All):
            results = [walk(c) for c in node.children]
            if Tri.FALSE in results:
                r = Tri.FALSE
            elif Tri.UNKNOWN in results:
                r = Tri.UNKNOWN
            else:
                r = Tri.TRUE
            return r
        elif isinstance(node, AnyOf):
            results = [walk(c) for c in node.children]
            if Tri.TRUE in results:
                r = Tri.TRUE
            elif Tri.UNKNOWN in results:
                r = Tri.UNKNOWN
            else:
                r = Tri.FALSE
            return r
        elif isinstance(node, Not):
            inner = walk(node.child)
            if inner is Tri.UNKNOWN:
                r = Tri.UNKNOWN
            elif inner is Tri.TRUE:
                r = Tri.FALSE
            else:
                r = Tri.TRUE
        else:  # pragma: no cover - validated earlier
            raise ValueError(f"unknown condition node: {node!r}")
        if isinstance(node, (AttrCompare, TimeRange, IPInNetworks)):
            leaves.append(LeafTrace(leaf=node, result=r))
        return r

    return walk(cond), leaves

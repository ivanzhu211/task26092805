"""条件求值（三值逻辑）。"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from . import iputil, timeutil
from .errors import ValidationError
from .models import (
    AllOf,
    AnyOf,
    AttrCompare,
    Condition,
    IpInNetworks,
    LeafTrace,
    Not,
    TimeRange,
    TriState,
)

_OPS = ("eq", "ne", "in", "gt", "lt")


def _category(value: Any) -> str | None:
    """属性值类别：布尔不算数字。"""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "str"
    return None


def _compare(op: str, actual: Any, expected: Any) -> TriState:
    cat_a, cat_e = _category(actual), _category(expected)
    if cat_a is None or cat_e is None or cat_a != cat_e:
        return TriState.UNKNOWN
    if op == "eq":
        return TriState.TRUE if actual == expected else TriState.FALSE
    if op == "ne":
        return TriState.TRUE if actual != expected else TriState.FALSE
    if cat_a == "bool":
        return TriState.UNKNOWN  # 布尔不支持大小比较
    if op == "gt":
        return TriState.TRUE if actual > expected else TriState.FALSE
    if op == "lt":
        return TriState.TRUE if actual < expected else TriState.FALSE
    raise ValidationError(f"未知比较操作: {op!r}")


def _eval_attr_compare(
    cond: AttrCompare, subject_attrs: dict[str, Any]
) -> tuple[TriState, str]:
    if cond.op not in _OPS:
        raise ValidationError(f"未知比较操作: {cond.op!r}")
    if cond.attr not in subject_attrs:
        return TriState.UNKNOWN, f"属性 {cond.attr!r} 缺失"
    actual = subject_attrs[cond.attr]
    if cond.op == "in":
        options = cond.value if isinstance(cond.value, (list, tuple)) else [cond.value]
        matched_any_type = False
        for option in options:
            r = _compare("eq", actual, option)
            if r is TriState.TRUE:
                return TriState.TRUE, f"{cond.attr!r}={actual!r} 在 {list(options)!r} 中"
            if r is not TriState.UNKNOWN:
                matched_any_type = True
        if not matched_any_type:
            return TriState.UNKNOWN, f"{cond.attr!r}={actual!r} 与候选类型不匹配"
        return TriState.FALSE, f"{cond.attr!r}={actual!r} 不在 {list(options)!r} 中"
    r = _compare(cond.op, actual, cond.value)
    if r is TriState.UNKNOWN:
        return r, f"{cond.attr!r}={actual!r} 与 {cond.value!r} 类型不匹配"
    return r, f"{cond.attr!r}={actual!r} {cond.op} {cond.value!r}"


def _sort_key(cond: Condition) -> str:
    return repr(cond)


def evaluate_condition(
    condition: Condition,
    subject_attrs: dict[str, Any],
    source_ip: str | None,
    moment: datetime,
    tz_name: str,
    leaf_traces: list[LeafTrace] | None = None,
) -> TriState:
    """对条件求三值结果；leaf_traces 非 None 时记录每个叶子。

    结果不随子条件书写顺序变化：子条件按稳定顺序求值。
    """
    if isinstance(condition, AttrCompare):
        result, detail = _eval_attr_compare(condition, subject_attrs)
        desc = f"属性比较 {condition.attr} {condition.op} {condition.value!r}"
        if leaf_traces is not None:
            leaf_traces.append(LeafTrace(desc, result, detail))
        return result
    if isinstance(condition, TimeRange):
        hit = timeutil.local_time_in_range(
            moment, tz_name, condition.start, condition.end
        )
        result = TriState.TRUE if hit else TriState.FALSE
        if leaf_traces is not None:
            local = moment.astimezone(timeutil.ZoneInfo(tz_name))
            leaf_traces.append(
                LeafTrace(
                    f"当地时间段 {condition.start}-{condition.end} ({tz_name})",
                    result,
                    f"当地时间 {local.strftime('%Y-%m-%d %H:%M:%S')}",
                )
            )
        return result
    if isinstance(condition, IpInNetworks):
        networks = [iputil.parse_network(n) for n in condition.networks]
        if source_ip is None:
            result, detail = TriState.UNKNOWN, "未提供来源 IP"
        else:
            hit = iputil.ip_in_networks(source_ip, networks)
            if hit is None:
                result, detail = TriState.UNKNOWN, f"来源 IP 不合法: {source_ip!r}"
            else:
                result = TriState.TRUE if hit else TriState.FALSE
                detail = f"来源 IP {source_ip} {'属于' if hit else '不属于'} {list(condition.networks)!r}"
        if leaf_traces is not None:
            leaf_traces.append(LeafTrace("来源IP网段", result, detail))
        return result
    if isinstance(condition, AllOf):
        results = [
            evaluate_condition(c, subject_attrs, source_ip, moment, tz_name, leaf_traces)
            for c in sorted(condition.children, key=_sort_key)
        ]
        if TriState.FALSE in results:
            return TriState.FALSE
        if TriState.UNKNOWN in results:
            return TriState.UNKNOWN
        return TriState.TRUE
    if isinstance(condition, AnyOf):
        results = [
            evaluate_condition(c, subject_attrs, source_ip, moment, tz_name, leaf_traces)
            for c in sorted(condition.children, key=_sort_key)
        ]
        if TriState.TRUE in results:
            return TriState.TRUE
        if TriState.UNKNOWN in results:
            return TriState.UNKNOWN
        return TriState.FALSE
    if isinstance(condition, Not):
        r = evaluate_condition(
            condition.child, subject_attrs, source_ip, moment, tz_name, leaf_traces
        )
        if r is TriState.UNKNOWN:
            return TriState.UNKNOWN
        return TriState.FALSE if r is TriState.TRUE else TriState.TRUE
    raise ValidationError(f"未知条件节点: {condition!r}")

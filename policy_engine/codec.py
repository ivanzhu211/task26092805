"""Condition / PolicyContent 的 JSON 编解码。"""
from __future__ import annotations

from typing import Any

from .errors import ValidationError
from .models import (
    AllOf,
    AnyOf,
    AttrCompare,
    Condition,
    Effect,
    IpInNetworks,
    Not,
    PolicyContent,
    TimeRange,
)


def condition_to_dict(cond: Condition) -> dict[str, Any]:
    if isinstance(cond, AttrCompare):
        return {"type": "attr", "attr": cond.attr, "op": cond.op, "value": cond.value}
    if isinstance(cond, TimeRange):
        return {"type": "time_range", "start": cond.start, "end": cond.end}
    if isinstance(cond, IpInNetworks):
        return {"type": "ip_in", "networks": list(cond.networks)}
    if isinstance(cond, AllOf):
        return {"type": "all", "children": [condition_to_dict(c) for c in cond.children]}
    if isinstance(cond, AnyOf):
        return {"type": "any", "children": [condition_to_dict(c) for c in cond.children]}
    if isinstance(cond, Not):
        return {"type": "not", "child": condition_to_dict(cond.child)}
    raise ValidationError(f"未知条件节点: {cond!r}")


def condition_from_dict(data: dict[str, Any]) -> Condition:
    t = data.get("type")
    if t == "attr":
        return AttrCompare(attr=data["attr"], op=data["op"], value=data["value"])
    if t == "time_range":
        return TimeRange(start=data["start"], end=data["end"])
    if t == "ip_in":
        return IpInNetworks(networks=tuple(data["networks"]))
    if t == "all":
        return AllOf(children=tuple(condition_from_dict(c) for c in data["children"]))
    if t == "any":
        return AnyOf(children=tuple(condition_from_dict(c) for c in data["children"]))
    if t == "not":
        return Not(child=condition_from_dict(data["child"]))
    raise ValidationError(f"未知条件类型: {t!r}")


def content_to_dict(content: PolicyContent) -> dict[str, Any]:
    return {
        "effect": content.effect.value,
        "actions": list(content.actions),
        "resource_tags": dict(content.resource_tags),
        "condition": condition_to_dict(content.condition),
    }


def content_from_dict(data: dict[str, Any]) -> PolicyContent:
    return PolicyContent(
        effect=Effect(data["effect"]),
        actions=tuple(data["actions"]),
        resource_tags=dict(data["resource_tags"]),
        condition=condition_from_dict(data["condition"]),
    )

"""核心数据类型定义（骨架）。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


class TriState(enum.Enum):
    """三值逻辑结果。"""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class AttrCompare:
    """叶子：主体属性比较。op ∈ {eq, ne, in, gt, lt}。"""

    attr: str
    op: str
    value: Any


@dataclass(frozen=True)
class TimeRange:
    """叶子：当地时间段，"HH:MM-HH:MM"，含起点不含终点。"""

    start: str
    end: str


@dataclass(frozen=True)
class IpInNetworks:
    """叶子：来源 IP 属于若干网段。"""

    networks: tuple[str, ...]


@dataclass(frozen=True)
class AllOf:
    children: tuple[Condition, ...]


@dataclass(frozen=True)
class AnyOf:
    children: tuple[Condition, ...]


@dataclass(frozen=True)
class Not:
    child: Condition


Condition = AttrCompare | TimeRange | IpInNetworks | AllOf | AnyOf | Not


@dataclass(frozen=True)
class PolicyContent:
    """一条策略的内容（某个版本的快照）。"""

    effect: Effect
    actions: tuple[str, ...]
    resource_tags: dict[str, str]
    condition: Condition


@dataclass(frozen=True)
class LeafTrace:
    """单个叶子的判定过程记录。"""

    description: str
    result: TriState
    detail: str = ""


@dataclass
class PolicyTrace:
    """单条策略参与判定的过程。"""

    policy_id: str
    node_id: str
    version: int
    effect: Effect
    overridden: bool
    override_node_id: Optional[str]
    override_kind: Optional[str]  # "replace" | "disable" | None
    condition_result: TriState
    participated: bool = True
    leaf_traces: list[LeafTrace] = field(default_factory=list)
    note: str = ""


@dataclass
class EvalReport:
    """求值结果与判定过程。"""

    decision: Effect
    traces: list[PolicyTrace] = field(default_factory=list)
    explanation: str = ""

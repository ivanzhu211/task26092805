"""Core type definitions for the policy engine."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


class Tri(enum.Enum):
    """Three-valued truth."""
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class AttrCompare:
    """Leaf: subject attribute comparison. op in {eq, ne, in, gt, lt}."""
    attr: str
    op: str
    value: Any


@dataclass(frozen=True)
class TimeRange:
    """Leaf: local time-of-day range, start inclusive, end exclusive."""
    start: str  # "HH:MM"
    end: str    # "HH:MM"


@dataclass(frozen=True)
class IPInNetworks:
    """Leaf: source IP belongs to one of the CIDR networks."""
    networks: tuple[str, ...]


@dataclass(frozen=True)
class All:
    children: tuple[Any, ...]


@dataclass(frozen=True)
class AnyOf:
    children: tuple[Any, ...]


@dataclass(frozen=True)
class Not:
    child: Any


@dataclass(frozen=True)
class PolicyContent:
    """Versioned content of a policy (also used as override replacement)."""
    effect: Effect
    actions: tuple[str, ...]
    resource_tags: dict[str, str]
    condition: Any  # condition tree built from the nodes above


@dataclass(frozen=True)
class LeafTrace:
    leaf: Any
    result: Tri


@dataclass(frozen=True)
class PolicyTrace:
    policy_id: str
    node_id: str
    version: Optional[int]          # None when content came from an override
    effect: "Effect"                # effect of the content used in judgment
    overridden: bool
    override_node_id: Optional[str]  # node whose override won, if any
    override_kind: Optional[str]     # "set" | "disable" | None
    applicable: bool                 # action + resource tags matched
    condition_result: Optional[Tri]  # None when not applicable
    leaves: tuple[LeafTrace, ...]


@dataclass(frozen=True)
class EvalResult:
    decision: Optional[Decision]     # None when replayable is False
    replayable: bool                 # False => cannot replay at requested time
    reason: Optional[str]            # set when replayable is False
    traces: tuple[PolicyTrace, ...]

"""求值引擎：合并规则（纯逻辑，不直接碰 SQLite）。"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from .conditions import evaluate_condition
from .models import (
    Effect,
    EvalReport,
    LeafTrace,
    PolicyContent,
    PolicyTrace,
    TriState,
)


@dataclass(frozen=True)
class EffectivePolicy:
    """某时刻对求值节点生效的一条策略（覆盖已解析、内容已替换）。"""

    policy_id: str
    node_id: str  # 策略定义所在节点
    version: int
    content: PolicyContent
    disabled: bool = False
    override_node_id: Optional[str] = None
    override_kind: Optional[str] = None  # "replace" | "disable" | None


def _applicable(content: PolicyContent, action: str, resource_tags: dict[str, str]) -> bool:
    if action not in content.actions:
        return False
    return all(resource_tags.get(k) == v for k, v in content.resource_tags.items())


def evaluate_snapshot(
    policies: list[EffectivePolicy],
    *,
    subject_attrs: dict[str, Any],
    resource_tags: dict[str, str],
    action: str,
    source_ip: str | None,
    moment: datetime,
    tz_name: str,
) -> EvalReport:
    """合并规则：
    1. 任一适用的拒绝策略条件为真或无法判定 → 拒绝；
    2. 否则有允许策略条件为真 → 允许；
    3. 其余一律拒绝。
    """
    traces: list[PolicyTrace] = []
    deny_hit = False
    allow_hit = False
    for policy in policies:
        if not _applicable(policy.content, action, resource_tags):
            continue
        trace = PolicyTrace(
            policy_id=policy.policy_id,
            node_id=policy.node_id,
            version=policy.version,
            effect=policy.content.effect,
            overridden=policy.override_kind is not None,
            override_node_id=policy.override_node_id,
            override_kind=policy.override_kind,
            condition_result=TriState.UNKNOWN,
        )
        if policy.disabled:
            trace.participated = False
            trace.note = "已被覆盖停用，不参与判定"
            traces.append(trace)
            continue
        leaf_traces: list[LeafTrace] = []
        result = evaluate_condition(
            policy.content.condition,
            subject_attrs,
            source_ip,
            moment,
            tz_name,
            leaf_traces,
        )
        trace.condition_result = result
        trace.leaf_traces = leaf_traces
        traces.append(trace)
        if policy.content.effect is Effect.DENY and result is not TriState.FALSE:
            deny_hit = True
        if policy.content.effect is Effect.ALLOW and result is TriState.TRUE:
            allow_hit = True
    if deny_hit:
        decision = Effect.DENY
        explanation = "存在适用的拒绝策略且其条件为真或无法判定，结果为拒绝"
    elif allow_hit:
        decision = Effect.ALLOW
        explanation = "无拒绝策略命中，存在允许策略条件为真，结果为允许"
    else:
        decision = Effect.DENY
        explanation = "无拒绝策略命中，也没有允许策略条件为真，按默认拒绝"
    return EvalReport(decision=decision, traces=traces, explanation=explanation)

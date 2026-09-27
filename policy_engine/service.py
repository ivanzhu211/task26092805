"""对外服务门面：写操作 + 求值/复盘。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from . import iputil, timeutil
from .codec import content_from_dict, content_to_dict
from .engine import EffectivePolicy, evaluate_snapshot
from .errors import (
    NonMonotonicTimeError,
    NotFoundError,
    ReplayUnavailableError,
    ValidationError,
)
from .models import (
    AllOf,
    AnyOf,
    AttrCompare,
    Condition,
    Effect,
    EvalReport,
    IpInNetworks,
    Not,
    PolicyContent,
    TimeRange,
)
from .store import Store

_MAX_LEVEL = 3
_ATTR_OPS = ("eq", "ne", "in", "gt", "lt")


def _to_ts(moment: datetime) -> float:
    """时间点统一转 Unix 时间戳；naive 时间按 UTC 处理。"""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _validate_attr_value(v: Any) -> None:
    if isinstance(v, bool):
        return
    if isinstance(v, (int, float, str)):
        return
    raise ValidationError(f"属性值只支持字符串、数字、布尔: {v!r}")


def _validate_condition(cond: Condition) -> None:
    if isinstance(cond, AttrCompare):
        if cond.op not in _ATTR_OPS:
            raise ValidationError(f"未知比较操作: {cond.op!r}")
        if cond.op == "in":
            if not isinstance(cond.value, (list, tuple)):
                raise ValidationError("in 操作的值必须是列表")
            for v in cond.value:
                _validate_attr_value(v)
        else:
            _validate_attr_value(cond.value)
    elif isinstance(cond, TimeRange):
        timeutil.validate_time_range(cond.start, cond.end)
    elif isinstance(cond, IpInNetworks):
        if not cond.networks:
            raise ValidationError("网段列表不能为空")
        for n in cond.networks:
            iputil.parse_network(n)
    elif isinstance(cond, (AllOf, AnyOf)):
        for c in cond.children:
            _validate_condition(c)
    elif isinstance(cond, Not):
        _validate_condition(cond.child)
    else:
        raise ValidationError(f"未知条件节点: {cond!r}")


def _validate_content(content: PolicyContent) -> None:
    if not isinstance(content.effect, Effect):
        raise ValidationError(f"未知效果: {content.effect!r}")
    if not content.actions or not all(isinstance(a, str) for a in content.actions):
        raise ValidationError("适用动作列表必须是非空字符串列表")
    if not all(
        isinstance(k, str) and isinstance(v, str)
        for k, v in content.resource_tags.items()
    ):
        raise ValidationError("资源标签要求必须是字符串键值对")
    _validate_condition(content.condition)


class PolicyService:
    """身份中台调用的入口。所有时间点参数由调用方给出，模块不读系统时钟。"""

    def __init__(self, db_path: str):
        self._store = Store(db_path)

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "PolicyService":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- 写入时钟 ----

    def _advance(self, write_time: datetime) -> tuple[float, int]:
        t = _to_ts(write_time)
        last = self._store.last_write_time()
        if last is not None and t < last:
            raise NonMonotonicTimeError(f"写入时间 {t} 早于上一次写入时间 {last}")
        seq = self._store.advance_clock(t)
        return t, seq

    # ---- 节点 ----

    def create_node(
        self,
        node_id: str,
        name: str,
        *,
        parent_id: Optional[str] = None,
        timezone_name: Optional[str] = None,
        write_time: datetime,
    ) -> None:
        if self._store.get_node(node_id) is not None:
            raise ValidationError(f"节点已存在: {node_id}")
        level = 1
        if parent_id is not None:
            parent = self._store.get_node(parent_id)
            if parent is None:
                raise NotFoundError(f"父节点不存在: {parent_id}")
            level = parent["level"] + 1
            if level > _MAX_LEVEL:
                raise ValidationError("组织节点最多三级")
        if timezone_name is not None:
            timeutil.validate_timezone(timezone_name)
        t, _ = self._advance(write_time)
        self._store.add_node(node_id, parent_id, name, timezone_name, level, t)
        self._store.commit()

    # ---- 策略 ----

    def create_policy(
        self,
        policy_id: str,
        node_id: str,
        content: PolicyContent,
        *,
        write_time: datetime,
    ) -> None:
        if self._store.get_node(node_id) is None:
            raise NotFoundError(f"节点不存在: {node_id}")
        if self._store.get_policy(policy_id) is not None:
            raise ValidationError(f"策略已存在: {policy_id}")
        _validate_content(content)
        t, seq = self._advance(write_time)
        self._store.add_policy(policy_id, node_id, t)
        self._store.add_version(
            policy_id, 1, t, seq, json.dumps(content_to_dict(content))
        )
        self._store.commit()

    def update_policy(
        self, policy_id: str, content: PolicyContent, *, write_time: datetime
    ) -> int:
        """修改策略，产生新版本，返回版本号。"""
        if self._store.get_policy(policy_id) is None:
            raise NotFoundError(f"策略不存在: {policy_id}")
        _validate_content(content)
        t, seq = self._advance(write_time)
        latest = self._store.latest_version(policy_id)
        version = latest["version"] + 1
        self._store.add_version(
            policy_id, version, t, seq, json.dumps(content_to_dict(content))
        )
        self._store.commit()
        return version

    def rollback_policy(
        self, policy_id: str, to_version: int, *, write_time: datetime
    ) -> int:
        """回滚到保留范围内的任一版本；回滚本身算一个新版本。"""
        if self._store.get_policy(policy_id) is None:
            raise NotFoundError(f"策略不存在: {policy_id}")
        target = self._store.get_version(policy_id, to_version)
        if target is None:
            latest = self._store.latest_version(policy_id)
            if latest is None or to_version < 1 or to_version > latest["version"]:
                raise NotFoundError(f"版本不存在: {policy_id} v{to_version}")
            raise ReplayUnavailableError(
                f"版本已被清理，无法回滚: {policy_id} v{to_version}"
            )
        t, seq = self._advance(write_time)
        latest = self._store.latest_version(policy_id)
        version = latest["version"] + 1
        self._store.add_version(policy_id, version, t, seq, target["content"])
        self._store.commit()
        return version

    # ---- 覆盖 ----

    def _check_override_target(self, policy_id: str, node_id: str) -> None:
        policy = self._store.get_policy(policy_id)
        if policy is None:
            raise NotFoundError(f"策略不存在: {policy_id}")
        if self._store.get_node(node_id) is None:
            raise NotFoundError(f"节点不存在: {node_id}")
        ancestor_ids = [r["node_id"] for r in self._store.get_path(node_id)][:-1]
        if policy["node_id"] not in ancestor_ids:
            raise ValidationError(
                f"不能覆盖非祖先节点上的策略: 策略在 {policy['node_id']}, 节点 {node_id}"
            )

    def register_override(
        self,
        policy_id: str,
        node_id: str,
        *,
        replacement: Optional[PolicyContent] = None,
        write_time: datetime,
    ) -> None:
        """登记覆盖：replacement 为 None 表示直接停用。"""
        self._check_override_target(policy_id, node_id)
        if replacement is not None:
            _validate_content(replacement)
        t, seq = self._advance(write_time)
        kind = "replace" if replacement is not None else "disable"
        content_json = (
            json.dumps(content_to_dict(replacement)) if replacement is not None else None
        )
        self._store.add_override_event(policy_id, node_id, kind, content_json, t, seq)
        self._store.commit()

    def revoke_override(
        self, policy_id: str, node_id: str, *, write_time: datetime
    ) -> None:
        """撤销覆盖。登记和撤销记录全部保留。"""
        self._check_override_target(policy_id, node_id)
        t, seq = self._advance(write_time)
        events = self._store.override_events_for([policy_id], [node_id], t)
        if not events or events[-1]["kind"] == "revoke":
            raise NotFoundError(f"没有生效中的覆盖可撤销: {policy_id} @ {node_id}")
        self._store.add_override_event(policy_id, node_id, "revoke", None, t, seq)
        self._store.commit()

    # ---- 求值 / 复盘 ----

    def evaluate(
        self,
        node_id: str,
        *,
        subject_attrs: dict[str, Any],
        resource_tags: dict[str, str],
        action: str,
        source_ip: Optional[str],
        at: datetime,
    ) -> EvalReport:
        """按 at 时刻实际生效的策略版本和覆盖状态判定（含等于 at 的修改）。"""
        path = self._store.get_path(node_id)
        if not path:
            raise NotFoundError(f"节点不存在: {node_id}")
        t = _to_ts(at)
        tz_name = self._effective_timezone(path)
        path_ids = [r["node_id"] for r in path]
        depth = {nid: i for i, nid in enumerate(path_ids)}

        policies = []
        for row in self._store.policies_for_nodes(path_ids):
            if row["created_at"] > t:
                continue  # 该时刻策略尚不存在
            vrow = self._store.version_at(row["policy_id"], t)
            if vrow is None:
                raise ReplayUnavailableError(
                    f"策略 {row['policy_id']} 在 {at} 生效的版本已被清理，无法复盘"
                )
            policies.append((row, vrow))

        events = self._store.override_events_for(
            [p["policy_id"] for p, _ in policies], path_ids, t
        )
        active: dict[tuple[str, str], Any] = {}
        for ev in events:
            key = (ev["policy_id"], ev["node_id"])
            if ev["kind"] == "revoke":
                active.pop(key, None)
            else:
                active[key] = ev

        snapshot: list[EffectivePolicy] = []
        for prow, vrow in policies:
            pid = prow["policy_id"]
            content = content_from_dict(json.loads(vrow["content"]))
            disabled = False
            override_node_id = None
            override_kind = None
            # 路径上离求值节点最近（最深）的生效覆盖
            best = None
            for (p, n), ev in active.items():
                if p != pid or depth[n] <= depth[prow["node_id"]]:
                    continue
                if best is None or depth[n] > depth[best["node_id"]]:
                    best = ev
            if best is not None:
                override_node_id = best["node_id"]
                override_kind = best["kind"]
                if best["kind"] == "disable":
                    disabled = True
                else:
                    content = content_from_dict(json.loads(best["content"]))
            snapshot.append(
                EffectivePolicy(
                    policy_id=pid,
                    node_id=prow["node_id"],
                    version=vrow["version"],
                    content=content,
                    disabled=disabled,
                    override_node_id=override_node_id,
                    override_kind=override_kind,
                )
            )
        moment = at if at.tzinfo is not None else at.replace(tzinfo=timezone.utc)
        return evaluate_snapshot(
            snapshot,
            subject_attrs=subject_attrs,
            resource_tags=resource_tags,
            action=action,
            source_ip=source_ip,
            moment=moment,
            tz_name=tz_name,
        )

    @staticmethod
    def _effective_timezone(path) -> str:
        tz = None
        for row in path:  # 根 → 叶，后者覆盖前者
            if row["timezone"]:
                tz = row["timezone"]
        return timeutil.resolve_timezone(None, tz)

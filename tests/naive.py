"""朴素实现：保留完整修改日志，求值时重放到目标时刻再判定。

不做任何版本清理与索引优化，用于和生产实现对比。
叶子求值复用 conditions/engine（叶子语义不在对比范围内），
版本选择、覆盖解析、时区继承等状态重建逻辑完全独立实现。
"""
from __future__ import annotations

from datetime import datetime, timezone

from policy_engine.engine import EffectivePolicy, evaluate_snapshot
from policy_engine.models import EvalReport

KEEP_VERSIONS = 20


class NaiveReplay:
    def __init__(self):
        self.log = []  # (t, op)，按写入顺序

    def record(self, t: float, op: tuple) -> None:
        self.log.append((t, op))

    def _replay(self, at: float):
        nodes = {}  # id -> (parent_id, timezone)
        policies = {}  # pid -> {"node_id", "created_at", "versions": [(v, t, content)]}
        overrides = []  # (policy_id, node_id, kind, content, t)，按写入顺序
        for t, op in self.log:
            kind = op[0]
            if kind == "create_node":
                _, node_id, parent_id, tz = op
                nodes[node_id] = (parent_id, tz)
                continue
            if t > at:
                continue  # 修改时间等于 at 的算已生效
            if kind == "create_policy":
                _, pid, node_id, content = op
                policies[pid] = {
                    "node_id": node_id,
                    "created_at": t,
                    "versions": [(1, t, content)],
                }
            elif kind == "update_policy":
                _, pid, content = op
                versions = policies[pid]["versions"]
                versions.append((versions[-1][0] + 1, t, content))
            elif kind == "rollback":
                _, pid, to_version = op
                versions = policies[pid]["versions"]
                content = next(c for v, _, c in versions if v == to_version)
                versions.append((versions[-1][0] + 1, t, content))
            elif kind == "override":
                _, pid, node_id, okind, content = op
                overrides.append((pid, node_id, okind, content, t))
            elif kind == "revoke":
                _, pid, node_id = op
                overrides.append((pid, node_id, "revoke", None, t))
            else:
                raise AssertionError(f"unknown op {op}")
        return nodes, policies, overrides

    def evaluate(
        self,
        node_id: str,
        *,
        subject_attrs,
        resource_tags,
        action,
        source_ip,
        at: datetime,
    ) -> EvalReport:
        t = at.timestamp()
        nodes, policies, overrides = self._replay(t)
        path = []
        cur = node_id
        while cur is not None:
            parent, _tz = nodes[cur]
            path.append(cur)
            cur = parent
        path.reverse()
        depth = {nid: i for i, nid in enumerate(path)}
        tz_name = "UTC"
        for nid in path:
            if nodes[nid][1]:
                tz_name = nodes[nid][1]
        active = {}
        for pid, nid, okind, content, ot in overrides:
            if nid not in depth:
                continue
            key = (pid, nid)
            if okind == "revoke":
                active.pop(key, None)
            else:
                active[key] = (okind, content)
        snapshot = []
        for pid, info in policies.items():
            if info["node_id"] not in depth:
                continue  # 只有路径上的策略参与判定
            if info["created_at"] > t:
                continue
            version, content = None, None
            for v, vt, vc in info["versions"]:
                if vt <= t:
                    version, content = v, vc
            disabled = False
            override_node_id = None
            override_kind = None
            best_depth = -1
            for (p, n), (okind, ocontent) in active.items():
                if p != pid or depth[n] <= depth[info["node_id"]]:
                    continue
                if depth[n] > best_depth:
                    best_depth = depth[n]
                    override_node_id = n
                    override_kind = okind
                    if okind == "disable":
                        disabled = True
                    else:
                        content = ocontent
            snapshot.append(
                EffectivePolicy(
                    policy_id=pid,
                    node_id=info["node_id"],
                    version=version,
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

    def replayable(self, node_id: str, at: datetime) -> bool:
        """该时刻对该节点是否可复盘：路径上策略的生效版本都在保留窗口内。"""
        t = at.timestamp()
        nodes, policies_now, _o = self._replay(float("inf"))  # 保留窗口对照最终版本数
        _n, policies, _o = self._replay(t)
        path = set()
        cur = node_id
        while cur is not None:
            path.add(cur)
            cur = nodes[cur][0]
        for pid, info in policies.items():
            if info["node_id"] not in path:
                continue
            if info["created_at"] > t:
                continue
            effective = None
            for v, vt, _c in info["versions"]:
                if vt <= t:
                    effective = v
            latest = policies_now[pid]["versions"][-1][0]
            if effective is not None and effective <= latest - KEEP_VERSIONS:
                return False
        return True

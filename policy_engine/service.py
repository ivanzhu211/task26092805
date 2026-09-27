"""Public facade used by the identity platform.

All timestamps are caller-supplied epoch seconds (int/float) or
timezone-aware datetimes. The service never reads the system clock.
"""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .conditions import evaluate_condition
from .storage import Store, content_from_json
from .types import (
    Decision, Effect, EvalResult, PolicyContent, PolicyTrace, Tri,
)


def _to_epoch(time) -> float:
    if isinstance(time, datetime):
        if time.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return time.timestamp()
    return float(time)


class PolicyService:
    def __init__(self, db_path: str):
        self.store = Store(db_path)

    def close(self) -> None:
        self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------- writes ----------------

    def add_node(self, node_id, parent_id, name, timezone_name=None, *,
                 time) -> None:
        if timezone_name is not None:
            ZoneInfo(timezone_name)  # validates the IANA name
        self.store.add_node(node_id, parent_id, name, timezone_name,
                            _to_epoch(time))

    def create_policy(self, policy_id, node_id, content: PolicyContent, *,
                      time) -> None:
        self.store.create_policy(policy_id, node_id, content, _to_epoch(time))

    def update_policy(self, policy_id, content: PolicyContent, *,
                      time) -> int:
        return self.store.update_policy(policy_id, content, _to_epoch(time))

    def rollback_policy(self, policy_id, target_version, *, time) -> int:
        return self.store.rollback_policy(policy_id, target_version,
                                          _to_epoch(time))

    def set_override(self, policy_id, node_id, content: PolicyContent, *,
                     time) -> None:
        self._check_ancestor(policy_id, node_id)
        self.store.put_override(policy_id, node_id, "set", content,
                                _to_epoch(time))

    def disable_override(self, policy_id, node_id, *, time) -> None:
        self._check_ancestor(policy_id, node_id)
        self.store.put_override(policy_id, node_id, "disable", None,
                                _to_epoch(time))

    def revoke_override(self, policy_id, node_id, *, time) -> None:
        self._check_ancestor(policy_id, node_id)
        self.store.revoke_override(policy_id, node_id, _to_epoch(time))

    def _check_ancestor(self, policy_id, node_id) -> None:
        policy = self.store.get_policy(policy_id)
        if policy is None:
            raise ValueError(f"policy not found: {policy_id}")
        path = self.store.get_path(node_id)
        # policy node must be a strict ancestor of the overriding node
        if not any(row[0] == policy[1] for row in path[:-1]):
            raise ValueError(
                f"policy {policy_id} is not on an ancestor of {node_id}")

    # ---------------- evaluation ----------------

    def evaluate(self, node_id, *, subject_attrs=None, resource_tags=None,
                 action=None, source_ip=None, time) -> EvalResult:
        t = _to_epoch(time)
        subject_attrs = subject_attrs or {}
        resource_tags = resource_tags or {}
        path = self.store.get_path(node_id)  # root -> node
        node_ids = [row[0] for row in path]
        depth_of = {row[0]: row[4] for row in path}

        tz_name = "UTC"
        for row in reversed(path):
            if row[3] is not None:
                tz_name = row[3]
                break
        local = datetime.fromtimestamp(t, ZoneInfo(tz_name))
        local_hhmm = f"{local.hour:02d}:{local.minute:02d}"

        traces: list[PolicyTrace] = []
        policies = self.store.policies_of_nodes(node_ids)
        live = [p for p in policies if p[2] <= t]  # created_at <= t
        override_rows = self.store.overrides_for(
            [p[0] for p in live], node_ids, t)

        # latest event per (policy, node); rows arrive ordered by (time, seq)
        latest: dict[tuple, tuple] = {}
        for pid, nid, _time, _seq, kind, content_json in override_rows:
            latest[(pid, nid)] = (kind, content_json)

        for pid, pnode, _created, _seq in sorted(
                live, key=lambda p: (depth_of[p[1]], p[0])):
            got = self.store.version_at(pid, t)
            if got is None:
                return EvalResult(
                    decision=None, replayable=False,
                    reason=(f"policy {pid}: the version in effect at "
                            f"time {t} has been pruned; cannot replay"),
                    traces=())
            version, content = got

            # nearest override on the path segment below the policy node
            override_node, override_kind, override_content = (
                None, None, None)
            pdepth = depth_of[pnode]
            for nid in node_ids:
                if depth_of[nid] <= pdepth:
                    continue
                event = latest.get((pid, nid))
                if event is None or event[0] == "revoke":
                    continue
                if (override_node is None
                        or depth_of[nid] > depth_of[override_node]):
                    override_node = nid
                    override_kind = event[0]
                    override_content = event[1]

            if override_kind == "disable":
                traces.append(PolicyTrace(
                    policy_id=pid, node_id=pnode, version=version,
                    effect=content.effect,
                    overridden=True, override_node_id=override_node,
                    override_kind="disable", applicable=False,
                    condition_result=None, leaves=()))
                continue
            if override_kind == "set":
                content = content_from_json(override_content)
                version = None  # content came from the override

            applicable = (
                action in content.actions
                and all(resource_tags.get(k) == v
                        for k, v in content.resource_tags.items()))
            if applicable:
                result, leaves = evaluate_condition(
                    content.condition, subject_attrs, source_ip, local_hhmm)
            else:
                result, leaves = None, ()
            traces.append(PolicyTrace(
                policy_id=pid, node_id=pnode, version=version,
                effect=content.effect,
                overridden=override_kind is not None,
                override_node_id=override_node,
                override_kind=override_kind,
                applicable=applicable, condition_result=result,
                leaves=tuple(leaves)))

        decision = self._merge(traces)
        return EvalResult(decision=decision, replayable=True,
                          reason=None, traces=tuple(traces))

    @staticmethod
    def _merge(traces: list[PolicyTrace]) -> Decision:
        # any applicable deny with TRUE/UNKNOWN condition => deny
        for tr in traces:
            if (tr.applicable and tr.effect is Effect.DENY
                    and tr.condition_result in (Tri.TRUE, Tri.UNKNOWN)):
                return Decision.DENY
        # else any applicable allow with TRUE condition => allow
        if any(tr.applicable and tr.effect is Effect.ALLOW
               and tr.condition_result is Tri.TRUE for tr in traces):
            return Decision.ALLOW
        return Decision.DENY

"""Naive reference implementation.

Keeps the complete write log in memory (no pruning) and, for each
evaluation, replays it up to the requested time before judging.
Property tests cross-check the real engine against this one.
"""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .conditions import evaluate_condition
from .storage import validate_content
from .types import (
    Decision, Effect, EvalResult, PolicyTrace, Tri,
)


class NaiveService:
    def __init__(self):
        self.nodes = {}          # id -> (parent_id, name, timezone)
        self.log = []            # (time, seq, kind, payload)
        self._last_time = float("-inf")
        self._seq = 0

    # ---------------- writes ----------------

    def _tick(self, time):
        time = float(time)
        if time < self._last_time:
            raise ValueError("write time goes backwards")
        self._last_time = time
        self._seq += 1
        return self._seq

    def add_node(self, node_id, parent_id, name, timezone_name=None, *,
                 time):
        if timezone_name is not None:
            ZoneInfo(timezone_name)
        depth = 1
        parent = parent_id
        while parent is not None:
            depth += 1
            parent = self.nodes[parent][0]
        if depth > 3:
            raise ValueError("org tree is at most 3 levels deep")
        self._tick(time)
        self.nodes[node_id] = (parent_id, name, timezone_name)

    def create_policy(self, policy_id, node_id, content, *, time):
        validate_content(content)
        seq = self._tick(time)
        self.log.append((float(time), seq, "create",
                         (policy_id, node_id, content)))

    def update_policy(self, policy_id, content, *, time):
        validate_content(content)
        seq = self._tick(time)
        self.log.append((float(time), seq, "update", (policy_id, content)))

    def rollback_policy(self, policy_id, target_version, *, time):
        seq = self._tick(time)
        self.log.append((float(time), seq, "rollback",
                         (policy_id, target_version)))

    def set_override(self, policy_id, node_id, content, *, time):
        validate_content(content)
        seq = self._tick(time)
        self.log.append((float(time), seq, "ovr",
                         (policy_id, node_id, "set", content)))

    def disable_override(self, policy_id, node_id, *, time):
        seq = self._tick(time)
        self.log.append((float(time), seq, "ovr",
                         (policy_id, node_id, "disable", None)))

    def revoke_override(self, policy_id, node_id, *, time):
        seq = self._tick(time)
        self.log.append((float(time), seq, "ovr",
                         (policy_id, node_id, "revoke", None)))

    # ---------------- evaluation ----------------

    def evaluate(self, node_id, *, subject_attrs=None, resource_tags=None,
                 action=None, source_ip=None, time):
        t = float(time)
        subject_attrs = subject_attrs or {}
        resource_tags = resource_tags or {}

        # path root -> node
        chain = []
        cur = node_id
        while cur is not None:
            parent, _name, _tz = self.nodes[cur]
            chain.append(cur)
            cur = parent
        chain.reverse()
        depth_of = {nid: i + 1 for i, nid in enumerate(chain)}

        tz_name = "UTC"
        for nid in reversed(chain):
            if self.nodes[nid][2] is not None:
                tz_name = self.nodes[nid][2]
                break
        local = datetime.fromtimestamp(t, ZoneInfo(tz_name))
        local_hhmm = f"{local.hour:02d}:{local.minute:02d}"

        # replay the full log up to t (time == t counts as effective;
        # ties broken by write order)
        versions = {}   # pid -> list of (version, time, seq, content)
        policy_node = {}
        created_at = {}
        overrides = {}  # (pid, nid) -> list of (time, seq, kind, content)
        for wtime, seq, kind, payload in self.log:
            if wtime > t:
                continue
            if kind == "create":
                pid, nid, content = payload
                policy_node[pid] = nid
                created_at[pid] = wtime
                versions.setdefault(pid, []).append((1, wtime, seq, content))
            elif kind == "update":
                pid, content = payload
                vs = versions[pid]
                vs.append((vs[-1][0] + 1, wtime, seq, content))
            elif kind == "rollback":
                pid, target = payload
                vs = versions[pid]
                content = next(c for v, _t, _s, c in vs if v == target)
                vs.append((vs[-1][0] + 1, wtime, seq, content))
            elif kind == "ovr":
                pid, nid, okind, content = payload
                overrides.setdefault((pid, nid), []).append(
                    (wtime, seq, okind, content))

        traces = []
        for pid in sorted(versions, key=lambda p: (depth_of.get(
                policy_node[p], 99), p)):
            if policy_node[pid] not in depth_of:
                continue  # policy not on this node's path
            if created_at[pid] > t:
                continue  # does not exist yet at t
            vs = [v for v in versions[pid] if v[1] <= t]
            version, _vt, _vs, content = max(vs, key=lambda v: (v[1], v[2]))

            # nearest override below the policy node
            ovr_node, ovr_kind, ovr_content = None, None, None
            for nid in chain:
                if depth_of[nid] <= depth_of[policy_node[pid]]:
                    continue
                events = overrides.get((pid, nid))
                if not events:
                    continue
                _et, _es, kind, ocontent = max(
                    events, key=lambda e: (e[0], e[1]))
                if kind == "revoke":
                    continue
                if ovr_node is None or depth_of[nid] > depth_of[ovr_node]:
                    ovr_node, ovr_kind, ovr_content = nid, kind, ocontent

            if ovr_kind == "disable":
                traces.append(PolicyTrace(
                    policy_id=pid, node_id=policy_node[pid],
                    version=version, effect=content.effect,
                    overridden=True, override_node_id=ovr_node,
                    override_kind="disable", applicable=False,
                    condition_result=None, leaves=()))
                continue
            if ovr_kind == "set":
                content = ovr_content
                version = None

            applicable = (
                action in content.actions
                and all(resource_tags.get(k) == v
                        for k, v in content.resource_tags.items()))
            if applicable:
                result, leaves = evaluate_condition(
                    content.condition, subject_attrs, source_ip, local_hhmm)
            else:
                result, leaves = None, []
            traces.append(PolicyTrace(
                policy_id=pid, node_id=policy_node[pid], version=version,
                effect=content.effect,
                overridden=ovr_kind is not None,
                override_node_id=ovr_node, override_kind=ovr_kind,
                applicable=applicable, condition_result=result,
                leaves=tuple(leaves)))

        decision = Decision.DENY
        for tr in traces:
            if (tr.applicable and tr.effect is Effect.DENY
                    and tr.condition_result in (Tri.TRUE, Tri.UNKNOWN)):
                decision = Decision.DENY
                break
        else:
            if any(tr.applicable and tr.effect is Effect.ALLOW
                   and tr.condition_result is Tri.TRUE for tr in traces):
                decision = Decision.ALLOW
        return EvalResult(decision=decision, replayable=True,
                          reason=None, traces=tuple(traces))

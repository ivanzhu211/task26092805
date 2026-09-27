"""随机修改序列：生产实现与朴素重放实现在任意可复盘时刻结果一致。"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from policy_engine import (
    AllOf,
    AnyOf,
    AttrCompare,
    Effect,
    IpInNetworks,
    Not,
    PolicyContent,
    PolicyService,
    ReplayUnavailableError,
    TimeRange,
)

from naive import NaiveReplay

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)

ATTR_VALUES = ["sales", "hr", "eng", 1, 5, 10, True, False, 0.5, "10"]
ATTR_NAMES = ["dept", "level", "vip", "region"]
NETWORKS = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32", "::ffff:172.16.0.0/108"]
IPS = ["10.1.2.3", "192.168.1.1", "2001:db8::5", "::ffff:10.9.9.9", "garbage", None]
ACTIONS = ["read", "write", "delete"]
TIMEZONES = ["UTC", "Asia/Shanghai", "America/New_York", None]


def rand_condition(rng, depth=0):
    if depth >= 2 or rng.random() < 0.45:
        kind = rng.choice(["attr", "time", "ip"])
        if kind == "attr":
            op = rng.choice(["eq", "ne", "in", "gt", "lt"])
            if op == "in":
                value = [rng.choice(ATTR_VALUES) for _ in range(rng.randint(1, 3))]
            else:
                value = rng.choice(ATTR_VALUES)
            return AttrCompare(rng.choice(ATTR_NAMES), op, value)
        if kind == "time":
            h1, h2 = rng.sample(range(24), 2)
            return TimeRange(f"{h1:02d}:00", f"{h2:02d}:00")
        return IpInNetworks(tuple(rng.sample(NETWORKS, rng.randint(1, 2))))
    kind = rng.choice(["all", "any", "not"])
    if kind == "not":
        return Not(rand_condition(rng, depth + 1))
    children = tuple(rand_condition(rng, depth + 1) for _ in range(rng.randint(1, 3)))
    return AllOf(children) if kind == "all" else AnyOf(children)


def rand_content(rng):
    tags = {}
    if rng.random() < 0.3:
        tags["env"] = rng.choice(["prod", "dev"])
    return PolicyContent(
        effect=rng.choice([Effect.ALLOW, Effect.DENY]),
        actions=tuple(rng.sample(ACTIONS, rng.randint(1, 2))),
        resource_tags=tags,
        condition=rand_condition(rng),
    )


def norm_trace(report):
    return sorted(
        (
            t.policy_id,
            t.node_id,
            t.version,
            t.participated,
            t.override_node_id,
            t.override_kind,
            t.condition_result.value,
            tuple((leaf.description, leaf.result.value) for leaf in t.leaf_traces),
        )
        for t in report.traces
    )


def run_fuzz(seed, tmp_path):
    rng = random.Random(seed)
    svc = PolicyService(str(tmp_path / f"fuzz_{seed}.db"))
    naive = NaiveReplay()
    clock = [T0]
    op_times = []

    def tick():
        clock[0] += timedelta(seconds=rng.choice([0, 0, 60, 300, 3600, 86400]))
        op_times.append(clock[0])
        return clock[0]

    # 组织树：1 公司、3 事业部、6 团队
    teams = []
    divs = []
    corp_tz = rng.choice(TIMEZONES)
    svc.create_node("corp", "公司", timezone_name=corp_tz, write_time=tick())
    naive.record(clock[0].timestamp(), ("create_node", "corp", None, corp_tz))
    for i in range(3):
        tz = rng.choice(TIMEZONES)
        svc.create_node(f"div{i}", f"事业部{i}", parent_id="corp",
                        timezone_name=tz, write_time=tick())
        naive.record(clock[0].timestamp(), ("create_node", f"div{i}", "corp", tz))
        divs.append(f"div{i}")
        for j in range(2):
            tid = f"team{i}{j}"
            tz = rng.choice(TIMEZONES)
            svc.create_node(tid, tid, parent_id=f"div{i}",
                            timezone_name=tz, write_time=tick())
            naive.record(clock[0].timestamp(), ("create_node", tid, f"div{i}", tz))
            teams.append(tid)

    descendants = {}
    for nid in ["corp"] + divs + teams:
        path = svc._store.get_path(nid)
        for row in path[:-1]:
            descendants.setdefault(row["node_id"], []).append(nid)

    versions = {}  # pid -> [version,...]（保留窗口内的）
    active_overrides = set()  # (pid, node_id)
    policies = []

    for step in range(160):
        roll = rng.random()
        if roll < 0.25 or len(policies) < 5:
            pid = f"p{step}"
            node = rng.choice(["corp"] + divs + teams)
            content = rand_content(rng)
            t = tick()
            svc.create_policy(pid, node, content, write_time=t)
            naive.record(t.timestamp(), ("create_policy", pid, node, content))
            policies.append(pid)
            versions[pid] = [1]
        elif roll < 0.55:
            # 更新：偏向热点策略以触发版本清理
            pid = policies[0] if rng.random() < 0.4 else rng.choice(policies)
            content = rand_content(rng)
            t = tick()
            v = svc.update_policy(pid, content, write_time=t)
            naive.record(t.timestamp(), ("update_policy", pid, content))
            versions[pid].append(v)
            versions[pid] = versions[pid][-20:]
        elif roll < 0.65 and any(len(vs) > 1 for vs in versions.values()):
            pid = rng.choice([p for p in policies if len(versions[p]) > 1])
            to_version = rng.choice(versions[pid])
            t = tick()
            v = svc.rollback_policy(pid, to_version, write_time=t)
            naive.record(t.timestamp(), ("rollback", pid, to_version))
            versions[pid].append(v)
            versions[pid] = versions[pid][-20:]
        elif roll < 0.85:
            pid = rng.choice(policies)
            pnode = svc._store.get_policy(pid)["node_id"]
            cands = descendants.get(pnode, [])
            if not cands:
                continue
            node = rng.choice(cands)
            t = tick()
            if rng.random() < 0.5:
                repl = rand_content(rng)
                svc.register_override(pid, node, replacement=repl, write_time=t)
                naive.record(t.timestamp(), ("override", pid, node, "replace", repl))
            else:
                svc.register_override(pid, node, write_time=t)
                naive.record(t.timestamp(), ("override", pid, node, "disable", None))
            active_overrides.add((pid, node))
        else:
            if not active_overrides:
                continue
            pid, node = rng.choice(sorted(active_overrides))
            t = tick()
            svc.revoke_override(pid, node, write_time=t)
            naive.record(t.timestamp(), ("revoke", pid, node))
            active_overrides.discard((pid, node))

    # 随机求值：覆盖整个时间线，并刻意命中写入时刻边界
    eval_nodes = ["corp"] + divs + teams
    n_replayable = n_unreplayable = 0
    for _ in range(400):
        if rng.random() < 0.3 and op_times:
            at = rng.choice(op_times)  # 恰好等于某次写入时间
        else:
            at = T0 + timedelta(
                seconds=rng.uniform(0, (clock[0] - T0).total_seconds() + 100)
            )
        node = rng.choice(eval_nodes)
        attrs = {}
        for name in ATTR_NAMES:
            if rng.random() < 0.6:
                attrs[name] = rng.choice(ATTR_VALUES)
        tags = {}
        if rng.random() < 0.5:
            tags["env"] = rng.choice(["prod", "dev"])
        kwargs = dict(
            subject_attrs=attrs,
            resource_tags=tags,
            action=rng.choice(ACTIONS),
            source_ip=rng.choice(IPS),
            at=at,
        )
        if naive.replayable(node, at):
            n_replayable += 1
            expected = naive.evaluate(node, **kwargs)
            actual = svc.evaluate(node, **kwargs)
            assert actual.decision is expected.decision, (
                f"decision mismatch at {at} node={node}: "
                f"{actual.decision} vs {expected.decision}"
            )
            assert norm_trace(actual) == norm_trace(expected), (
                f"trace mismatch at {at} node={node}"
            )
        else:
            n_unreplayable += 1
            with pytest.raises(ReplayUnavailableError):
                svc.evaluate(node, **kwargs)
    svc.close()
    return n_replayable, n_unreplayable


def test_fuzz_seed_1(tmp_path):
    n_ok, n_skip = run_fuzz(20260928, tmp_path)
    assert n_ok > 100  # 确保有足够多的有效对比


def test_fuzz_seed_2(tmp_path):
    run_fuzz(42, tmp_path)


def test_fuzz_seed_3(tmp_path):
    run_fuzz(7, tmp_path)

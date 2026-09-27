"""Property test: random write sequences; the real engine must agree with
the naive full-log-replaying reference at every replayable time point."""
import random

import pytest

from policy_engine import (
    All, AnyOf, AttrCompare, Effect, IPInNetworks, Not, PolicyContent,
    PolicyService, TimeRange,
)
from policy_engine.naive import NaiveService
from policy_engine.storage import MAX_VERSIONS

T0 = 1_700_000_000
NODES = {  # id -> (parent, timezone)
    "corp": (None, "Asia/Shanghai"),
    "d1": ("corp", None),
    "d2": ("corp", "America/New_York"),
    "t1": ("d1", None),
    "t2": ("d1", "Europe/Berlin"),
    "t3": ("d2", None),
    "t4": ("d2", None),
}
ACTIONS = ("read", "write", "export")


def rand_condition(rng, depth=0):
    if depth >= 2 or rng.random() < 0.5:
        kind = rng.randrange(3)
        if kind == 0:
            return rng.choice([
                AttrCompare("dept", "eq", rng.choice(["eng", "sales"])),
                AttrCompare("dept", "ne", "ops"),
                AttrCompare("dept", "in", ["eng", "ops"]),
                AttrCompare("level", rng.choice(["gt", "lt"]),
                            rng.randint(0, 5)),
                AttrCompare("vip", "eq", rng.choice([True, False, 1])),
            ])
        if kind == 1:
            return rng.choice([
                TimeRange("22:00", "06:00"),
                TimeRange("09:00", "18:00"),
                TimeRange("00:00", "12:00"),
            ])
        return IPInNetworks((rng.choice([
            "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32",
            "::ffff:10.0.0.0/104"]),))
    comb = rng.randrange(3)
    if comb == 0:
        return All(tuple(rand_condition(rng, depth + 1)
                         for _ in range(rng.randint(1, 3))))
    if comb == 1:
        return AnyOf(tuple(rand_condition(rng, depth + 1)
                           for _ in range(rng.randint(1, 3))))
    return Not(rand_condition(rng, depth + 1))


def rand_content(rng):
    tags = {}
    if rng.random() < 0.4:
        tags["env"] = rng.choice(["prod", "dev"])
    return PolicyContent(
        effect=rng.choice([Effect.ALLOW, Effect.DENY]),
        actions=tuple(rng.sample(ACTIONS, rng.randint(1, 2))),
        resource_tags=tags,
        condition=rand_condition(rng),
    )


def rand_attrs(rng):
    attrs = {}
    if rng.random() < 0.8:
        attrs["dept"] = rng.choice(["eng", "sales", "ops"])
    if rng.random() < 0.7:
        attrs["level"] = rng.choice([0, 2, 4, "high", True])
    if rng.random() < 0.5:
        attrs["vip"] = rng.choice([True, False, 1, "yes"])
    return attrs


def rand_ip(rng):
    return rng.choice(["10.1.2.3", "192.168.3.4", "::ffff:10.9.8.7",
                       "2001:db8::1", "2001:db9::1", "not-an-ip", None])


def run_one_seed(seed):
    rng = random.Random(seed)
    real = PolicyService(":memory:")
    naive = NaiveService()
    now = T0
    for nid, (parent, tz) in NODES.items():
        real.add_node(nid, parent, nid, tz, time=now)
        naive.add_node(nid, parent, nid, tz, time=now)
        now += 1

    policies = []          # policy ids
    version_times = {}     # pid -> list of (version, time)
    policy_node = {}       # pid -> node id
    overridable = []       # (policy_id, node_id) valid override targets

    def tick():
        nonlocal now
        if rng.random() < 0.3:
            return now          # tie: later write must win
        now += rng.randint(1, 3600)
        return now

    def ancestors_of(nid):
        chain = []
        cur = NODES[nid][0]
        while cur is not None:
            chain.append(cur)
            cur = NODES[cur][0]
        return chain

    for _ in range(150):
        op = rng.randrange(10)
        t = tick()
        if op < 3 and len(policies) < 8:          # create
            pid = f"p{len(policies)}"
            nid = rng.choice(list(NODES))
            content = rand_content(rng)
            real.create_policy(pid, nid, content, time=t)
            naive.create_policy(pid, nid, content, time=t)
            policies.append(pid)
            version_times[pid] = [(1, t)]
            policy_node[pid] = nid
            for other in NODES:
                if nid in ancestors_of(other):
                    overridable.append((pid, other))
        elif op < 6 and policies:                  # update
            pid = rng.choice(policies)
            content = rand_content(rng)
            real.update_policy(pid, content, time=t)
            naive.update_policy(pid, content, time=t)
            version_times[pid].append((version_times[pid][-1][0] + 1, t))
        elif op == 6 and policies:                 # rollback (retained only)
            pid = rng.choice(policies)
            vmax = version_times[pid][-1][0]
            lo = max(1, vmax - (MAX_VERSIONS - 1))
            target = rng.randint(lo, vmax)
            real.rollback_policy(pid, target, time=t)
            naive.rollback_policy(pid, target, time=t)
            version_times[pid].append((vmax + 1, t))
        elif op < 9 and overridable:               # override set/disable
            pid, nid = rng.choice(overridable)
            if rng.random() < 0.5:
                content = rand_content(rng)
                real.set_override(pid, nid, content, time=t)
                naive.set_override(pid, nid, content, time=t)
            else:
                real.disable_override(pid, nid, time=t)
                naive.disable_override(pid, nid, time=t)
        elif overridable:                          # revoke
            pid, nid = rng.choice(overridable)
            real.revoke_override(pid, nid, time=t)
            naive.revoke_override(pid, nid, time=t)
        if policies and rng.random() < 0.08:
            # burst of updates to push a policy past the 20-version window
            pid = rng.choice(policies)
            for _ in range(rng.randint(19, 25)):
                t = tick()
                content = rand_content(rng)
                real.update_policy(pid, content, time=t)
                naive.update_policy(pid, content, time=t)
                version_times[pid].append((version_times[pid][-1][0] + 1, t))

        # evaluate at random past times after some writes
        if rng.random() < 0.6:
            for _ in range(2):
                et = rng.uniform(T0 - 10, now)
                check(real, naive, version_times, policy_node, rng, et)
    real.close()


def check(real, naive, version_times, policy_node, rng, et):
    nid = rng.choice(list(NODES))
    kw = dict(subject_attrs=rand_attrs(rng),
              resource_tags=rng.choice([{}, {"env": "prod"},
                                        {"env": "dev"}]),
              action=rng.choice(ACTIONS + ("delete",)),
              source_ip=rand_ip(rng))
    got = real.evaluate(nid, time=et, **kw)
    want = naive.evaluate(nid, time=et, **kw)

    # independently determine whether replay at `et` should be possible:
    # for every path policy created by then, the version in effect at et
    # must still be retained (last MAX_VERSIONS versions are kept)
    chain = set()
    cur = nid
    while cur is not None:
        chain.add(cur)
        cur = NODES[cur][0]
    replayable = True
    for pid, vs in version_times.items():
        if policy_node[pid] not in chain or vs[0][1] > et:
            continue
        vmax = vs[-1][0]
        needed = max(v for v, t in vs if t <= et)
        if needed <= vmax - MAX_VERSIONS:
            replayable = False
    assert got.replayable == replayable, (et, nid)
    if not got.replayable:
        assert got.decision is None and got.reason
        return

    got_traces = [(tr.policy_id, tr.node_id, tr.version, tr.effect,
                   tr.overridden, tr.override_node_id, tr.override_kind,
                   tr.applicable, tr.condition_result, tr.leaves)
                  for tr in got.traces]
    want_traces = [(tr.policy_id, tr.node_id, tr.version, tr.effect,
                    tr.overridden, tr.override_node_id, tr.override_kind,
                    tr.applicable, tr.condition_result, tr.leaves)
                   for tr in want.traces]
    assert got.decision == want.decision, (et, nid, kw)
    assert got_traces == want_traces, (et, nid, kw)


@pytest.mark.parametrize("seed", range(30))
def test_random_sequences_match_naive(seed):
    run_one_seed(seed)

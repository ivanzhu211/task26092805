"""Service-level evaluation: merge rules, overrides, versions, replay."""
from datetime import datetime, timezone

import pytest

from policy_engine import (
    All, AnyOf, AttrCompare, Decision, Effect, IPInNetworks, Not,
    PolicyContent, PolicyService, TimeRange, Tri,
)

UTC = timezone.utc


def ts(y, mo, d, h, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=UTC).timestamp()


ALLOW_ENG = PolicyContent(Effect.ALLOW, ("read",), {},
                          AttrCompare("dept", "eq", "eng"))
DENY_NIGHT = PolicyContent(Effect.DENY, ("read",), {},
                           TimeRange("22:00", "06:00"))


@pytest.fixture
def svc():
    s = PolicyService(":memory:")
    base = ts(2026, 1, 1, 0)
    s.add_node("corp", None, "Corp", "Asia/Shanghai", time=base)
    s.add_node("div1", "corp", "Div1", None, time=base + 1)
    s.add_node("div2", "corp", "Div2", None, time=base + 2)
    s.add_node("team1", "div1", "Team1", None, time=base + 3)
    s.add_node("team2", "div1", "Team2", None, time=base + 4)
    yield s
    s.close()


# ---------- merge rules ----------

def test_deny_with_unknown_condition_denies(svc):
    # subject attr missing -> condition UNKNOWN -> deny still applies
    svc.create_policy("p", "corp",
                      PolicyContent(Effect.DENY, ("read",), {},
                                    AttrCompare("clearance", "eq", "high")),
                      time=ts(2026, 2, 1, 0))
    r = svc.evaluate("team1", subject_attrs={}, action="read",
                     time=ts(2026, 2, 2, 0))
    assert r.decision is Decision.DENY
    assert r.traces[0].condition_result is Tri.UNKNOWN


def test_allow_true_plus_deny_unknown_is_deny(svc):
    svc.create_policy("pa", "corp", ALLOW_ENG, time=ts(2026, 2, 1, 0))
    svc.create_policy("pd", "div1",
                      PolicyContent(Effect.DENY, ("read",), {},
                                    AttrCompare("mystery", "eq", 1)),
                      time=ts(2026, 2, 1, 1))
    r = svc.evaluate("team1", subject_attrs={"dept": "eng"}, action="read",
                     time=ts(2026, 2, 2, 0))
    assert r.decision is Decision.DENY


def test_default_deny_when_nothing_matches(svc):
    svc.create_policy("pa", "corp", ALLOW_ENG, time=ts(2026, 2, 1, 0))
    r = svc.evaluate("team1", subject_attrs={"dept": "sales"},
                     action="read", time=ts(2026, 2, 2, 0))
    assert r.decision is Decision.DENY
    # action not covered -> policy not applicable
    r2 = svc.evaluate("team1", subject_attrs={"dept": "eng"},
                      action="write", time=ts(2026, 2, 2, 0))
    assert r2.decision is Decision.DENY
    assert not r2.traces[0].applicable


def test_resource_tags_must_all_match(svc):
    svc.create_policy("pa", "corp",
                      PolicyContent(Effect.ALLOW, ("read",),
                                    {"env": "prod", "tier": "gold"},
                                    AttrCompare("dept", "eq", "eng")),
                      time=ts(2026, 2, 1, 0))
    kw = dict(subject_attrs={"dept": "eng"}, action="read",
              time=ts(2026, 2, 2, 0))
    assert svc.evaluate("team1", resource_tags={"env": "prod",
                        "tier": "gold"}, **kw).decision is Decision.ALLOW
    assert svc.evaluate("team1", resource_tags={"env": "prod"},
                        **kw).decision is Decision.DENY
    assert svc.evaluate("team1", resource_tags={"env": "prod",
                        "tier": "silver"}, **kw).decision is Decision.DENY


# ---------- DST ----------

@pytest.fixture
def ny_svc():
    s = PolicyService(":memory:")
    s.add_node("corp", None, "Corp", "America/New_York", time=ts(2025, 1, 1, 0))
    yield s
    s.close()


def test_dst_fall_back_repeated_hour_counts_twice(ny_svc):
    # 2025-11-02: 02:00 EDT -> 01:00 EST; 01:xx happens twice
    ny_svc.create_policy("p", "corp",
                         PolicyContent(Effect.ALLOW, ("read",), {},
                                       TimeRange("01:00", "02:00")),
                         time=ts(2025, 6, 1, 0))
    first = ts(2025, 11, 2, 5, 30)   # 01:30 EDT
    second = ts(2025, 11, 2, 6, 30)  # 01:30 EST
    before = ts(2025, 11, 2, 4, 30)  # 00:30 EDT
    after = ts(2025, 11, 2, 7, 30)   # 02:30 EST
    for t, expected in [(first, Decision.ALLOW), (second, Decision.ALLOW),
                        (before, Decision.DENY), (after, Decision.DENY)]:
        r = ny_svc.evaluate("corp", action="read", time=t)
        assert r.decision is expected, (t, r.decision)


def test_dst_spring_forward_skipped_hour_never_matches(ny_svc):
    # 2026-03-08: 02:00 EST -> 03:00 EDT; 02:xx never occurs locally
    ny_svc.create_policy("p", "corp",
                         PolicyContent(Effect.ALLOW, ("read",), {},
                                       TimeRange("02:00", "03:00")),
                         time=ts(2025, 6, 1, 0))
    for hour_utc in range(5, 12):  # sweep the whole transition window
        r = ny_svc.evaluate("corp", action="read",
                            time=ts(2026, 3, 8, hour_utc, 30))
        assert r.decision is Decision.DENY, hour_utc


# ---------- overrides ----------

def test_multilevel_override_and_revoke(svc):
    svc.create_policy("p", "corp", DENY_NIGHT, time=ts(2026, 2, 1, 0))
    # nights at 23:00 Asia/Shanghai == 15:00 UTC, interleaved with writes
    night1 = ts(2026, 2, 3, 15)  # after team1's disable, before its revoke
    night2 = ts(2026, 2, 4, 15)  # after team1's revoke
    night3 = ts(2026, 2, 5, 15)  # after div1's revoke

    # div1 replaces content with always-allow; team1 disables the policy
    svc.set_override("p", "div1", ALLOW_ENG, time=ts(2026, 2, 2, 0))
    svc.disable_override("p", "team1", time=ts(2026, 2, 3, 0))

    # team1: nearest override (its own disable) wins
    r = svc.evaluate("team1", subject_attrs={"dept": "eng"}, action="read",
                     time=night1)
    assert r.decision is Decision.DENY  # nothing applicable -> default deny
    tr = r.traces[0]
    assert tr.overridden and tr.override_kind == "disable"
    assert tr.override_node_id == "team1"

    # team2: inherits div1's replacement (allow for eng)
    r = svc.evaluate("team2", subject_attrs={"dept": "eng"}, action="read",
                     time=night1)
    assert r.decision is Decision.ALLOW
    tr = r.traces[0]
    assert tr.overridden and tr.override_kind == "set"
    assert tr.override_node_id == "div1" and tr.version is None

    # div2: no override on its path -> base deny applies
    svc.add_node("team3", "div2", "Team3", time=ts(2026, 2, 3, 1))
    r = svc.evaluate("team3", subject_attrs={"dept": "eng"}, action="read",
                     time=night1)
    assert r.decision is Decision.DENY
    assert not r.traces[0].overridden

    # team1 revokes its override -> falls back to div1's replacement
    svc.revoke_override("p", "team1", time=ts(2026, 2, 4, 0))
    r = svc.evaluate("team1", subject_attrs={"dept": "eng"}, action="read",
                     time=night2)
    assert r.decision is Decision.ALLOW
    assert r.traces[0].override_node_id == "div1"

    # replay before the revoke: team1's disable still in effect
    r = svc.evaluate("team1", subject_attrs={"dept": "eng"}, action="read",
                     time=night1)
    assert r.traces[0].override_kind == "disable"

    # div1 revokes too -> base policy everywhere
    svc.revoke_override("p", "div1", time=ts(2026, 2, 5, 0))
    r = svc.evaluate("team2", subject_attrs={"dept": "eng"}, action="read",
                     time=night3)
    assert r.decision is Decision.DENY
    assert not r.traces[0].overridden


def test_cannot_override_non_ancestor_policy(svc):
    svc.create_policy("p", "div2", ALLOW_ENG, time=ts(2026, 2, 1, 0))
    with pytest.raises(ValueError):
        svc.set_override("p", "team1", ALLOW_ENG, time=ts(2026, 2, 2, 0))
    with pytest.raises(ValueError):
        svc.disable_override("p", "team1", time=ts(2026, 2, 2, 0))
    # and a node cannot "override" a policy sitting on itself
    svc.create_policy("q", "div1", ALLOW_ENG, time=ts(2026, 2, 1, 1))
    with pytest.raises(ValueError):
        svc.disable_override("q", "div1", time=ts(2026, 2, 2, 0))


# ---------- versions & rollback ----------

def test_version_20_21_boundary_replay(svc):
    t0 = ts(2026, 2, 1, 0)
    svc.create_policy("p", "corp", DENY_NIGHT, time=t0)
    for i in range(19):          # -> v20
        svc.update_policy("p", DENY_NIGHT, time=t0 + 1 + i)
    # v1..v20 all retained; replay at v1's time works
    r = svc.evaluate("corp", action="read", time=t0)
    assert r.replayable and r.traces[0].version == 1

    svc.update_policy("p", DENY_NIGHT, time=t0 + 20)   # v21, v1 pruned
    r = svc.evaluate("corp", action="read", time=t0)
    assert not r.replayable and r.decision is None
    assert "p" in r.reason
    # v2 still replayable
    r = svc.evaluate("corp", action="read", time=t0 + 1)
    assert r.replayable and r.traces[0].version == 2

    svc.update_policy("p", DENY_NIGHT, time=t0 + 21)   # v22, v2 pruned
    r = svc.evaluate("corp", action="read", time=t0 + 1)
    assert not r.replayable
    r = svc.evaluate("corp", action="read", time=t0 + 2)
    assert r.replayable and r.traces[0].version == 3


def test_rollback_then_replay_pre_rollback(svc):
    deny = PolicyContent(Effect.DENY, ("read",), {},
                         AttrCompare("dept", "eq", "eng"))
    t0 = ts(2026, 2, 1, 0)
    svc.create_policy("p", "corp", ALLOW_ENG, time=t0)          # v1 allow
    svc.update_policy("p", deny, time=t0 + 1000)                # v2 deny
    svc.rollback_policy("p", 1, time=t0 + 2000)                 # v3 == v1

    attrs = {"dept": "eng"}
    # before the update: allow
    r = svc.evaluate("corp", subject_attrs=attrs, action="read",
                     time=t0 + 500)
    assert r.decision is Decision.ALLOW and r.traces[0].version == 1
    # between update and rollback: deny
    r = svc.evaluate("corp", subject_attrs=attrs, action="read",
                     time=t0 + 1500)
    assert r.decision is Decision.DENY and r.traces[0].version == 2
    # after rollback: allow again, as a NEW version v3
    r = svc.evaluate("corp", subject_attrs=attrs, action="read",
                     time=t0 + 2500)
    assert r.decision is Decision.ALLOW and r.traces[0].version == 3


def test_rollback_to_pruned_version_rejected(svc):
    t0 = ts(2026, 2, 1, 0)
    svc.create_policy("p", "corp", ALLOW_ENG, time=t0)
    for i in range(20):
        svc.update_policy("p", ALLOW_ENG, time=t0 + 1 + i)  # v21, v1 gone
    with pytest.raises(ValueError):
        svc.rollback_policy("p", 1, time=t0 + 100)
    r = svc.evaluate("corp", action="read", time=t0 + 200)
    assert r.replayable  # failed rollback produced no version


# ---------- write clock ----------

def test_write_clock_monotonic_and_ties(svc):
    t0 = ts(2026, 2, 1, 0)
    svc.create_policy("p", "corp", ALLOW_ENG, time=t0)
    with pytest.raises(ValueError):
        svc.update_policy("p", ALLOW_ENG, time=t0 - 1)
    # same timestamp twice: the later write wins
    deny = PolicyContent(Effect.DENY, ("read",), {},
                         AttrCompare("dept", "eq", "eng"))
    svc.update_policy("p", deny, time=t0)
    r = svc.evaluate("corp", subject_attrs={"dept": "eng"}, action="read",
                     time=t0)
    assert r.decision is Decision.DENY and r.traces[0].version == 2


def test_modification_at_exact_eval_time_is_effective(svc):
    t0 = ts(2026, 2, 1, 0)
    svc.create_policy("p", "corp", ALLOW_ENG, time=t0)
    r = svc.evaluate("corp", subject_attrs={"dept": "eng"}, action="read",
                     time=t0)
    assert r.decision is Decision.ALLOW
    # before creation the policy does not exist
    r = svc.evaluate("corp", subject_attrs={"dept": "eng"}, action="read",
                     time=t0 - 1)
    assert r.decision is Decision.DENY and r.traces == ()


# ---------- trace content ----------

def test_trace_reports_leaves_and_origin(svc):
    cond = All((AttrCompare("dept", "eq", "eng"),
                AnyOf((IPInNetworks(("10.0.0.0/8",)),
                       Not(AttrCompare("guest", "eq", True))))))
    svc.create_policy("p", "div1",
                      PolicyContent(Effect.ALLOW, ("read",), {}, cond),
                      time=ts(2026, 2, 1, 0))
    r = svc.evaluate("team1", subject_attrs={"dept": "eng", "guest": False},
                     action="read", source_ip="192.168.1.1",
                     time=ts(2026, 2, 2, 0))
    assert r.decision is Decision.ALLOW
    tr = r.traces[0]
    assert tr.policy_id == "p" and tr.node_id == "div1" and tr.version == 1
    assert len(tr.leaves) == 3

    def leaf_result(leaf):
        return next(l.result for l in tr.leaves if l.leaf == leaf)

    dept_leaf = cond.children[0]
    ip_leaf = cond.children[1].children[0]
    guest_leaf = cond.children[1].children[1].child
    assert leaf_result(dept_leaf) is Tri.TRUE    # dept matches
    assert leaf_result(ip_leaf) is Tri.FALSE     # wrong subnet
    assert leaf_result(guest_leaf) is Tri.FALSE  # guest is False

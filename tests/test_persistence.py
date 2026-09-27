"""File-backed storage: state and the write clock survive a restart."""
import pytest

from policy_engine import (
    AttrCompare, Decision, Effect, PolicyContent, PolicyService, TimeRange,
)

T0 = 1_700_000_000


def test_state_survives_reopen(tmp_path):
    db = str(tmp_path / "state.db")
    svc = PolicyService(db)
    svc.add_node("corp", None, "Corp", "UTC", time=T0)
    svc.add_node("team", "corp", "Team", None, time=T0 + 1)
    svc.create_policy("p", "corp",
                      PolicyContent(Effect.ALLOW, ("read",), {},
                                    AttrCompare("dept", "eq", "eng")),
                      time=T0 + 2)
    svc.update_policy("p",
                      PolicyContent(Effect.DENY, ("read",), {},
                                    TimeRange("22:00", "06:00")),
                      time=T0 + 3)
    svc.close()

    svc2 = PolicyService(db)
    # write clock restored: cannot go backwards
    with pytest.raises(ValueError):
        svc2.update_policy("p", PolicyContent(Effect.ALLOW, ("read",), {},
                                              AttrCompare("a", "eq", 1)),
                           time=T0 + 1)
    # replay at both version windows still works
    kw = dict(subject_attrs={"dept": "eng"}, action="read")
    r = svc2.evaluate("team", time=T0 + 2, **kw)
    assert r.decision is Decision.ALLOW and r.traces[0].version == 1
    r = svc2.evaluate("team", time=T0 + 3, **kw)
    assert r.decision is Decision.DENY and r.traces[0].version == 2
    # and new writes continue the version sequence
    assert svc2.update_policy("p", PolicyContent(
        Effect.ALLOW, ("read",), {}, AttrCompare("a", "eq", 1)),
        time=T0 + 4) == 3
    svc2.close()

"""服务层：多级覆盖与撤销、版本边界复盘、回滚复盘、写入时钟。"""
from datetime import datetime, timedelta, timezone

import pytest

from policy_engine import (
    AllOf,
    AttrCompare,
    Effect,
    NonMonotonicTimeError,
    NotFoundError,
    PolicyContent,
    PolicyService,
    ReplayUnavailableError,
    TimeRange,
    TriState,
    ValidationError,
)

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def ts(hours=0, minutes=0):
    return T0 + timedelta(hours=hours, minutes=minutes)


def allow_dept(dept):
    return PolicyContent(Effect.ALLOW, ("read",), {}, AttrCompare("dept", "eq", dept))


@pytest.fixture()
def svc(tmp_path):
    s = PolicyService(str(tmp_path / "test.db"))
    s.create_node("corp", "公司", timezone_name="Asia/Shanghai", write_time=ts(0))
    s.create_node("div1", "事业部A", parent_id="corp", write_time=ts(0))
    s.create_node("div2", "事业部B", parent_id="corp", write_time=ts(0))
    s.create_node("team1", "团队1", parent_id="div1", write_time=ts(0))
    yield s
    s.close()


def ev_read(svc, node, dept="sales", at=None, ip=None):
    return svc.evaluate(
        node,
        subject_attrs={"dept": dept},
        resource_tags={},
        action="read",
        source_ip=ip,
        at=at or ts(500),
    )


def test_node_level_limit(svc):
    with pytest.raises(ValidationError):
        svc.create_node("x", "超层", parent_id="team1", write_time=ts(1))


def test_non_monotonic_write_time_rejected(svc):
    svc.create_policy("p1", "corp", allow_dept("sales"), write_time=ts(10))
    with pytest.raises(NonMonotonicTimeError):
        svc.create_policy("p2", "corp", allow_dept("hr"), write_time=ts(9))
    # 时间相同允许，后写的生效
    svc.create_policy("p2", "corp", allow_dept("hr"), write_time=ts(10))


def test_deny_unknown_forces_deny(svc):
    svc.create_policy(
        "p_allow", "corp", allow_dept("sales"), write_time=ts(1)
    )
    svc.create_policy(
        "p_deny",
        "corp",
        PolicyContent(Effect.DENY, ("read",), {}, AttrCompare("missing", "eq", 1)),
        write_time=ts(1),
    )
    r = ev_read(svc, "team1")
    assert r.decision is Effect.DENY
    deny_trace = [t for t in r.traces if t.policy_id == "p_deny"][0]
    assert deny_trace.condition_result is TriState.UNKNOWN


def test_multi_level_override_and_revoke(svc):
    svc.create_policy("p", "corp", allow_dept("sales"), write_time=ts(1))
    # 事业部级停用
    svc.register_override("p", "div1", write_time=ts(2))
    assert ev_read(svc, "team1").decision is Effect.DENY
    # 团队级替换（离 team1 更近，优先于 div1 的停用）
    svc.register_override("p", "team1", replacement=allow_dept("vip"), write_time=ts(3))
    assert ev_read(svc, "team1", dept="sales").decision is Effect.DENY
    assert ev_read(svc, "team1", dept="vip").decision is Effect.ALLOW
    # 撤销团队级覆盖 → 事业部的停用重新生效
    svc.revoke_override("p", "team1", write_time=ts(4))
    assert ev_read(svc, "team1", dept="vip").decision is Effect.DENY
    # 撤销事业部覆盖 → 原策略恢复
    svc.revoke_override("p", "div1", write_time=ts(5))
    assert ev_read(svc, "team1").decision is Effect.ALLOW
    # 复盘：ts(2) 之后、ts(3) 之前 div1 停用生效
    assert ev_read(svc, "team1", at=ts(2, 30)).decision is Effect.DENY
    # 复盘：ts(3) 团队替换生效
    assert ev_read(svc, "team1", dept="vip", at=ts(3, 30)).decision is Effect.ALLOW
    # 其他分支不受影响
    svc.create_node("team2", "团队2", parent_id="div2", write_time=ts(6))
    assert ev_read(svc, "team2").decision is Effect.ALLOW


def test_cannot_override_non_ancestor(svc):
    svc.create_policy("p", "div1", allow_dept("sales"), write_time=ts(1))
    with pytest.raises(ValidationError):
        svc.register_override("p", "div2", write_time=ts(2))
    with pytest.raises(ValidationError):
        svc.register_override("p", "corp", write_time=ts(2))


def test_revoke_without_active_override(svc):
    svc.create_policy("p", "corp", allow_dept("sales"), write_time=ts(1))
    with pytest.raises(NotFoundError):
        svc.revoke_override("p", "team1", write_time=ts(2))


def test_version_20_21_boundary_replay(svc):
    svc.create_policy("p", "corp", allow_dept("v1"), write_time=ts(1))
    for v in range(2, 22):  # v2..v21，共 21 个版本
        svc.update_policy("p", allow_dept(f"v{v}"), write_time=ts(1 + v))
    # 第 21 个版本写入后，v1 被清理，v2 是保留的最早版本
    # ts(3) 时刻 v2 生效（v2 写入于 ts(3)）→ 可复盘
    r = svc.evaluate(
        "team1",
        subject_attrs={"dept": "v2"},
        resource_tags={},
        action="read",
        source_ip=None,
        at=ts(3),
    )
    assert r.decision is Effect.ALLOW
    assert [t for t in r.traces if t.policy_id == "p"][0].version == 2
    # ts(2) 时刻 v1 生效，但 v1 已被清理 → 明确报告无法复盘
    with pytest.raises(ReplayUnavailableError):
        svc.evaluate(
            "team1",
            subject_attrs={"dept": "v1"},
            resource_tags={},
            action="read",
            source_ip=None,
            at=ts(2),
        )
    # 策略创建之前 → 策略不存在，不报错
    r = svc.evaluate(
        "team1",
        subject_attrs={"dept": "v1"},
        resource_tags={},
        action="read",
        source_ip=None,
        at=ts(0, 30),
    )
    assert r.decision is Effect.DENY and len(r.traces) == 0


def test_rollback_and_replay_before_rollback(svc):
    svc.create_policy("p", "corp", allow_dept("v1"), write_time=ts(1))
    svc.update_policy("p", allow_dept("v2"), write_time=ts(2))
    new_version = svc.rollback_policy("p", 1, write_time=ts(3))
    assert new_version == 3
    # 回滚后：v1 内容生效
    assert ev_read(svc, "team1", dept="v1").decision is Effect.ALLOW
    assert ev_read(svc, "team1", dept="v2").decision is Effect.DENY
    # 复盘回滚前：v2 生效
    assert ev_read(svc, "team1", dept="v2", at=ts(2, 30)).decision is Effect.ALLOW
    assert ev_read(svc, "team1", dept="v1", at=ts(2, 30)).decision is Effect.DENY
    # 回滚到已清理版本 → 报错
    for v in range(4, 25):
        svc.update_policy("p", allow_dept(f"x{v}"), write_time=ts(10 + v))
    with pytest.raises(ReplayUnavailableError):
        svc.rollback_policy("p", 1, write_time=ts(100))


def test_modification_at_exact_eval_time_is_effective(svc):
    svc.create_policy("p", "corp", allow_dept("sales"), write_time=ts(1))
    svc.update_policy("p", allow_dept("hr"), write_time=ts(5))
    # 修改时间等于求值时间点 → 算已生效
    assert ev_read(svc, "team1", dept="hr", at=ts(5)).decision is Effect.ALLOW
    assert ev_read(svc, "team1", dept="sales", at=ts(5)).decision is Effect.DENY


def test_timezone_inheritance(svc):
    # corp 设了 Asia/Shanghai，team1 继承；夜间段按北京时间判断
    svc.create_policy(
        "p_night",
        "corp",
        PolicyContent(Effect.DENY, ("read",), {}, TimeRange("22:00", "06:00")),
        write_time=ts(1),
    )
    svc.create_policy("p_allow", "corp", allow_dept("sales"), write_time=ts(1))
    beijing_night = datetime(2026, 1, 1, 15, 0, tzinfo=UTC)  # 北京 23:00
    beijing_day = datetime(2026, 1, 1, 2, 0, tzinfo=UTC)  # 北京 10:00
    assert ev_read(svc, "team1", at=beijing_night).decision is Effect.DENY
    assert ev_read(svc, "team1", at=beijing_day).decision is Effect.ALLOW


def test_time_range_equal_endpoints_rejected_at_save(svc):
    with pytest.raises(ValidationError):
        svc.create_policy(
            "p",
            "corp",
            PolicyContent(Effect.DENY, ("read",), {}, TimeRange("08:00", "08:00")),
            write_time=ts(1),
        )


def test_trace_reports_override_info(svc):
    svc.create_policy("p", "corp", allow_dept("sales"), write_time=ts(1))
    svc.register_override("p", "div1", replacement=allow_dept("vip"), write_time=ts(2))
    r = ev_read(svc, "team1", dept="vip")
    trace = [t for t in r.traces if t.policy_id == "p"][0]
    assert trace.overridden and trace.override_node_id == "div1"
    assert trace.override_kind == "replace"
    assert trace.node_id == "corp" and trace.version == 1
    assert r.decision is Effect.ALLOW

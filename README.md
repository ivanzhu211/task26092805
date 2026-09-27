# policy-engine：多级组织访问策略求值与复盘模块

供身份中台调用的纯 Python 库（无接口层），数据持久化在本地 SQLite 文件。
支持按当前策略模拟判定，也支持按过去某一时刻实际生效的策略版本与覆盖
状态复盘，并给出可读的判定过程。

## 快速开始

```python
from datetime import datetime, timezone
from policy_engine import (
    PolicyService, PolicyContent, Effect,
    AttrCompare, TimeRange, IpInNetworks, AllOf, AnyOf, Not,
)

svc = PolicyService("policies.db")
T = datetime(2026, 9, 1, tzinfo=timezone.utc)

# 组织树：公司 → 事业部 → 团队（最多三级；时区缺省继承最近祖先，否则 UTC）
svc.create_node("corp", "公司", timezone_name="Asia/Shanghai", write_time=T)
svc.create_node("div1", "事业部", parent_id="corp", write_time=T)
svc.create_node("team1", "团队", parent_id="div1", write_time=T)

# 策略：效果 + 适用动作 + 资源标签要求 + 条件
svc.create_policy("p1", "corp", PolicyContent(
    effect=Effect.ALLOW,
    actions=("read",),
    resource_tags={"env": "prod"},
    condition=AllOf((
        AttrCompare("dept", "eq", "sales"),
        Not(TimeRange("22:00", "06:00")),          # 当地时间段，含起点不含终点
        IpInNetworks(("10.0.0.0/8", "2001:db8::/32")),
    )),
), write_time=T)

# 下级覆盖：替换内容，或直接停用（replacement=None）；可撤销
svc.register_override("p1", "team1", replacement=None, write_time=T)
svc.revoke_override("p1", "team1", write_time=T)

# 求值 / 复盘：at 给出时间点，按当时生效的版本与覆盖状态判定
report = svc.evaluate(
    "team1",
    subject_attrs={"dept": "sales"},
    resource_tags={"env": "prod"},
    action="read",
    source_ip="10.1.2.3",
    at=datetime(2026, 9, 2, 15, 0, tzinfo=timezone.utc),
)
print(report.decision, report.explanation)
for trace in report.traces:      # 每条策略的来源节点、版本、覆盖情况、叶子结果
    print(trace)
```

## 规则摘要

- **版本**：每次修改产生新版本（从 1 递增），每条策略只保留最近 20 个
  版本；`rollback_policy` 回滚到保留范围内任一版本，回滚本身算新版本。
  复盘所需版本已被清理时抛 `ReplayUnavailableError`，绝不拿别的版本凑数。
- **覆盖**：下级可对祖先策略登记覆盖（替换/停用）或撤销，记录全部保留；
  对求值节点生效的是路径上离它最近的那次生效覆盖。
- **合并**：任一适用的拒绝策略条件为真或无法判定 → 拒绝；否则有允许策略
  条件为真 → 允许；其余一律拒绝。
- **三值条件**：属性缺失、类型不匹配、IP 不合法 → 无法判定；`all`/`any`/
  `not` 语义与顺序无关。布尔不算数字。
- **时间**：写操作与求值的时间点都由调用方给出，模块不读系统时钟；写入
  时间单调不减，相同时间后写的为准；修改时间等于求值时间点算已生效。
- **时区**：时间段按求值节点的生效时区判断；夏令时回拨时重复钟点都算，
  拨快时跳过的钟点不存在。

## 测试与性能验证

```bash
python3 -m pytest tests/ -q      # 37 个测试，含随机序列 vs 朴素重放一致性
python3 scripts/perf_check.py    # 100 节点/5000 策略/10 万覆盖下求值 < 20ms
```

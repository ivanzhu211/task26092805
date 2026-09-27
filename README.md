# policy-engine

多级组织访问策略求值与复盘库。供身份中台以库的形式直接调用（无接口层），
数据持久化在本地 SQLite 文件中。仅依赖 Python 标准库（3.9+）。

## 能力

- 按**当前**策略模拟判定；按**过去任一时刻**实际生效的策略版本与覆盖状态复盘，
  并返回可读的判定过程（每条策略来自哪个节点、哪个版本、是否被谁覆盖、
  每个条件叶子的结果）。
- 三级组织树（公司/事业部/团队），节点可设 IANA 时区，未设则沿用最近祖先，
  都没有则为 UTC。
- 每条策略保留最近 20 个版本，可回滚到保留范围内任一版本（回滚本身也是新版本）。
  覆盖登记/撤销记录永久保留。
- 所有写操作与求值的时间点均由调用方给出，模块不读系统时钟。

## 快速开始

```python
from policy_engine import (
    All, AttrCompare, Effect, IPInNetworks, PolicyContent, PolicyService,
    TimeRange,
)

svc = PolicyService("policies.db")
svc.add_node("corp", None, "总公司", "Asia/Shanghai", time=1000)
svc.add_node("div1", "corp", "事业部", None, time=1001)   # 时区沿用总公司
svc.add_node("team1", "div1", "团队", None, time=1002)

svc.create_policy("p1", "corp", PolicyContent(
    effect=Effect.DENY,
    actions=("read", "export"),
    resource_tags={"env": "prod"},
    condition=All((
        TimeRange("22:00", "06:00"),                 # 跨午夜，含头不含尾
        IPInNetworks(("10.0.0.0/8", "2001:db8::/32")),
    )),
), time=1003)

result = svc.evaluate(
    "team1",
    subject_attrs={"dept": "eng"},
    resource_tags={"env": "prod"},
    action="read",
    source_ip="::ffff:10.1.2.3",                     # IPv4 映射地址按 IPv4 算
    time=1700000000,                                  # 判定/复盘的时间点
)
result.decision        # Decision.ALLOW / Decision.DENY / None（无法复盘时）
result.replayable      # False 表示该时刻所需版本已被清理，无法复盘
result.traces          # 每条参与策略的判定过程与叶子结果
```

## 写操作

| 方法 | 说明 |
|---|---|
| `add_node(id, parent_id, name, timezone=None, *, time)` | 建组织节点，最多三级 |
| `create_policy(id, node_id, content, *, time)` | 建策略，版本从 1 开始 |
| `update_policy(id, content, *, time)` | 修改策略，产生新版本；只保留最近 20 版 |
| `rollback_policy(id, target_version, *, time)` | 回滚到保留范围内的版本，本身是新版本 |
| `set_override(pid, node_id, content, *, time)` | 下级节点覆盖祖先策略（替换内容） |
| `disable_override(pid, node_id, *, time)` | 下级节点停用祖先策略 |
| `revoke_override(pid, node_id, *, time)` | 撤销本节点的覆盖 |

写入时间不得早于上一次写入；时间相同时后写的生效。修改时间等于求值时间点的，
算已生效；早于策略创建时间的求值，该策略视为不存在。

## 语义要点

- **条件叶子**：主体属性比较（`eq/ne/in/gt/lt`，布尔不算数字）、当地时间段
  （按请求节点生效时区；夏令时回拨重复钟点都算，拨快跳过的不存在）、
  来源 IP 属于若干网段（IPv4/IPv6；主机位非 0 的网段保存时拒绝）。
- **三值逻辑**：属性缺失、类型不匹配、IP 不合法 → 叶子「无法判定」。
  `all` 有假即假、否则有无法判定即无法判定；`any` 对称；`not(无法判定)=无法判定`。
  结果与子条件顺序无关。
- **合并**：任一适用的拒绝策略条件为真或无法判定 → 拒绝；否则有允许策略
  条件为真 → 允许；其余一律拒绝。策略适用 = 动作匹配且资源标签要求全部满足。
- **覆盖**：对节点生效的是路径上离它最近的覆盖；撤销后回落到上一级覆盖
  （没有则用原策略）。不能覆盖非祖先节点上的策略。

## 性能

求值只访问该节点路径上的策略与覆盖记录（均有索引），耗时与全平台策略总数、
覆盖记录总量无关。在 100 节点 / 5000 策略 / 10 万覆盖记录的数据集上，
单次求值中位数约 2ms（见 `tests/test_performance.py`）。

## 测试

```
python3 -m pytest tests/ -q
```

覆盖：跨午夜、夏令时切换、IPv4 映射地址、布尔与数字比较、子条件乱序、
拒绝策略无法判定、多级覆盖与撤销、第 20/21 版本边界复盘、回滚后复盘
回滚前时刻、持久化重开、规模性能；另有属性测试：随机修改序列下，
任意可复盘时间点的结果与按完整修改日志重放的朴素实现
（`policy_engine/naive.py`）完全一致。

## 模块结构

- `policy_engine/types.py` — 条件树、策略内容、判定结果等类型
- `policy_engine/conditions.py` — 条件校验与三值求值
- `policy_engine/storage.py` — SQLite schema、写入时钟、按时间点读取
- `policy_engine/service.py` — 对外门面 `PolicyService`
- `policy_engine/naive.py` — 朴素参考实现（供属性测试对照）

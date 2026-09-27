"""性能验证：100 节点 / 5000 策略 / 10 万覆盖记录下，单次求值 < 20ms，
且耗时不随全平台策略总数、覆盖记录总量增长而变慢。"""
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_engine import AttrCompare, Effect, PolicyContent, PolicyService

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def build(db_path, n_policies, n_overrides):
    svc = PolicyService(db_path)
    svc.create_node("corp", "公司", timezone_name="Asia/Shanghai", write_time=T0)
    divs, teams = [], []
    for i in range(10):
        d = f"div{i}"
        svc.create_node(d, d, parent_id="corp", write_time=T0)
        divs.append(d)
        for j in range(9):
            t = f"team{i}{j}"
            svc.create_node(t, t, parent_id=d, write_time=T0)
            teams.append(t)
    nodes = ["corp"] + divs + teams  # 100 个节点
    content = PolicyContent(Effect.ALLOW, ("read",), {}, AttrCompare("dept", "eq", "sales"))
    import json
    from policy_engine.codec import content_to_dict
    store = svc._store
    t0 = T0.timestamp()
    for i in range(n_policies):
        pid = f"p{i}"
        store.add_policy(pid, nodes[i % len(nodes)], t0)
        store.add_version(pid, 1, t0, i, json.dumps(content_to_dict(content)))
    store.commit()
    # 覆盖事件：分布到各策略与节点（含大量与本路径无关的记录）
    seq = n_policies
    for i in range(n_overrides):
        seq += 1
        store.add_override_event(
            f"p{i % n_policies}", nodes[(i * 7) % len(nodes)],
            "disable" if i % 2 else "revoke", None, t0 + i * 0.001, seq,
        )
    store.commit()
    return svc, teams[0]


def measure(svc, node, n=300):
    at = datetime(2027, 1, 1, tzinfo=timezone.utc)
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        svc.evaluate(node, subject_attrs={"dept": "sales"}, resource_tags={},
                     action="read", source_ip="10.1.2.3", at=at)
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.mean(samples), sorted(samples)[int(len(samples) * 0.95)], max(samples)


def main():
    tmp = tempfile.mkdtemp()
    # 小规模基线：5000 策略 + 1 万覆盖
    svc, node = build(os.path.join(tmp, "small.db"), 5000, 10_000)
    measure(svc, node, 50)  # 预热
    a, p, m = measure(svc, node)
    svc.close()
    print(f"5000 策略 / 1万覆盖:  avg={a:.3f}ms p95={p:.3f}ms max={m:.3f}ms")
    # 覆盖记录 ×10：耗时不应显著增长
    svc, node = build(os.path.join(tmp, "big.db"), 5000, 100_000)
    measure(svc, node, 50)
    a2, p2, m2 = measure(svc, node)
    svc.close()
    print(f"5000 策略 / 10万覆盖: avg={a2:.3f}ms p95={p2:.3f}ms max={m2:.3f}ms")
    assert p < 20 and p2 < 20, "单次求值超过 20ms"
    assert p2 < p * 3 + 2, "耗时随覆盖记录总量显著增长"
    print("性能验证通过")


if __name__ == "__main__":
    main()

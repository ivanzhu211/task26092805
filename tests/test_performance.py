"""Scale sanity: eval latency depends only on the node's own path."""
import json
import random
import time

import pytest

from policy_engine import (
    AttrCompare, Effect, PolicyContent, PolicyService, TimeRange,
)
from policy_engine.storage import content_to_json

T0 = 1_700_000_000


def _seed_bulk(db_path):
    """100 nodes, 5000 policies, 100k override records."""
    svc = PolicyService(db_path)
    now = T0
    svc.add_node("corp", None, "Corp", "Asia/Shanghai", time=now)
    divs = [f"div{i}" for i in range(9)]
    teams = [f"team{i}" for i in range(90)]
    for i, d in enumerate(divs):
        now += 1
        svc.add_node(d, "corp", d, None, time=now)
    for i, t in enumerate(teams):
        now += 1
        svc.add_node(t, divs[i % 9], t, None, time=now)

    content = PolicyContent(Effect.DENY, ("read",), {},
                            TimeRange("22:00", "06:00"))
    blob = content_to_json(content)
    conn = svc.store.conn
    nodes = ["corp"] + divs + teams
    rng = random.Random(7)
    now += 1
    # 5000 policies, each with one version
    conn.executemany(
        "INSERT INTO policies(id,node_id,created_at,created_seq) "
        "VALUES(?,?,?,?)",
        [(f"pol{i}", nodes[i % 100], float(now), i) for i in range(5000)])
    conn.executemany(
        "INSERT INTO policy_versions(policy_id,version,time,seq,content) "
        "VALUES(?,?,?,?,?)",
        [(f"pol{i}", 1, float(now), i, blob) for i in range(5000)])
    # 100k override records spread across all policies and nodes
    conn.executemany(
        "INSERT INTO overrides(policy_id,node_id,time,seq,kind,content) "
        "VALUES(?,?,?,?,?,?)",
        [(f"pol{rng.randrange(5000)}", nodes[rng.randrange(100)],
          float(now), 5000 + i, "disable", None)
         for i in range(100_000)])
    conn.commit()
    svc.store._last_time = float(now)  # keep the in-memory clock in sync
    return svc, now


def test_eval_latency_at_scale(tmp_path):
    db = tmp_path / "perf.db"
    svc, now = _seed_bulk(str(db))
    svc.create_policy("target", "corp",
                      PolicyContent(Effect.ALLOW, ("read",), {},
                                    AttrCompare("dept", "eq", "eng")),
                      time=now + 1)

    kw = dict(subject_attrs={"dept": "eng"}, action="read", time=now + 2)
    svc.evaluate("team17", **kw)  # warm up
    samples = []
    for _ in range(30):
        start = time.perf_counter()
        svc.evaluate("team17", **kw)
        samples.append((time.perf_counter() - start) * 1000)
    samples.sort()
    median = samples[len(samples) // 2]
    assert median < 20, f"median eval {median:.2f}ms exceeds 20ms"
    svc.close()

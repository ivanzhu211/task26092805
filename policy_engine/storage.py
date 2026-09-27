"""SQLite persistence layer: schema, writes, and point-in-time reads.

All write/read timestamps are supplied by the caller (epoch seconds).
The store never reads the system clock.
"""
from __future__ import annotations

import json
import sqlite3

from .conditions import validate_condition
from .types import (
    All, AnyOf, AttrCompare, Effect, IPInNetworks, Not, PolicyContent,
    TimeRange,
)

MAX_VERSIONS = 20
MAX_DEPTH = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes(
  id TEXT PRIMARY KEY,
  parent_id TEXT,
  name TEXT NOT NULL,
  timezone TEXT,
  depth INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policies(
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  created_at REAL NOT NULL,
  created_seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pol_node ON policies(node_id);
CREATE TABLE IF NOT EXISTS policy_versions(
  policy_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  time REAL NOT NULL,
  seq INTEGER NOT NULL,
  content TEXT NOT NULL,
  PRIMARY KEY(policy_id, version)
);
CREATE INDEX IF NOT EXISTS idx_pv_time
  ON policy_versions(policy_id, time, seq);
CREATE TABLE IF NOT EXISTS overrides(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  time REAL NOT NULL,
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL,
  content TEXT
);
CREATE INDEX IF NOT EXISTS idx_ov
  ON overrides(policy_id, node_id, time, seq);
"""


# ---------- (de)serialization ----------

def condition_to_json(cond) -> dict:
    if isinstance(cond, AttrCompare):
        return {"t": "attr", "attr": cond.attr, "op": cond.op,
                "value": cond.value}
    if isinstance(cond, TimeRange):
        return {"t": "time", "start": cond.start, "end": cond.end}
    if isinstance(cond, IPInNetworks):
        return {"t": "ip", "networks": list(cond.networks)}
    if isinstance(cond, All):
        return {"t": "all",
                "children": [condition_to_json(c) for c in cond.children]}
    if isinstance(cond, AnyOf):
        return {"t": "any",
                "children": [condition_to_json(c) for c in cond.children]}
    if isinstance(cond, Not):
        return {"t": "not", "child": condition_to_json(cond.child)}
    raise ValueError(f"unknown condition node: {cond!r}")


def condition_from_json(data: dict):
    t = data["t"]
    if t == "attr":
        return AttrCompare(data["attr"], data["op"], data["value"])
    if t == "time":
        return TimeRange(data["start"], data["end"])
    if t == "ip":
        return IPInNetworks(tuple(data["networks"]))
    if t == "all":
        return All(tuple(condition_from_json(c) for c in data["children"]))
    if t == "any":
        return AnyOf(tuple(condition_from_json(c) for c in data["children"]))
    if t == "not":
        return Not(condition_from_json(data["child"]))
    raise ValueError(f"unknown condition tag: {t!r}")


def content_to_json(content: PolicyContent) -> str:
    return json.dumps({
        "effect": content.effect.value,
        "actions": list(content.actions),
        "resource_tags": dict(content.resource_tags),
        "condition": condition_to_json(content.condition),
    })


def content_from_json(text: str) -> PolicyContent:
    data = json.loads(text)
    return PolicyContent(
        effect=Effect(data["effect"]),
        actions=tuple(data["actions"]),
        resource_tags=dict(data["resource_tags"]),
        condition=condition_from_json(data["condition"]),
    )


def validate_content(content: PolicyContent) -> None:
    if not isinstance(content.effect, Effect):
        raise ValueError("effect must be Effect.ALLOW or Effect.DENY")
    if not content.actions:
        raise ValueError("actions must not be empty")
    for key, value in content.resource_tags.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("resource tags must be str->str")
    validate_condition(content.condition)


# ---------- store ----------

class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(_SCHEMA)
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='last_time'").fetchone()
        self._last_time = float(row[0]) if row else float("-inf")
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='last_seq'").fetchone()
        self._seq = int(row[0]) if row else 0

    def close(self) -> None:
        self.conn.close()

    # -- write clock --

    def _tick(self, time: float) -> int:
        time = float(time)
        if time < self._last_time:
            raise ValueError(
                f"write time {time} goes backwards (last={self._last_time})")
        self._last_time = time
        self._seq += 1
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES('last_time',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (repr(self._last_time),))
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES('last_seq',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(self._seq),))
        return self._seq

    # -- nodes --

    def add_node(self, node_id, parent_id, name, timezone, time) -> None:
        seq = self._tick(time)
        del seq
        depth = 1
        if parent_id is not None:
            row = self.conn.execute(
                "SELECT depth FROM nodes WHERE id=?", (parent_id,)).fetchone()
            if row is None:
                raise ValueError(f"parent node not found: {parent_id}")
            depth = row[0] + 1
            if depth > MAX_DEPTH:
                raise ValueError("org tree is at most 3 levels deep")
        self.conn.execute(
            "INSERT INTO nodes(id,parent_id,name,timezone,depth) "
            "VALUES(?,?,?,?,?)",
            (node_id, parent_id, name, timezone, depth))
        self.conn.commit()

    def get_node(self, node_id):
        return self.conn.execute(
            "SELECT id,parent_id,name,timezone,depth FROM nodes WHERE id=?",
            (node_id,)).fetchone()

    def get_path(self, node_id):
        """Nodes from root down to node_id (inclusive)."""
        path = []
        current = node_id
        while current is not None:
            row = self.get_node(current)
            if row is None:
                raise ValueError(f"node not found: {current}")
            path.append(row)
            current = row[1]
        path.reverse()
        return path

    # -- policies --

    def create_policy(self, policy_id, node_id, content, time) -> None:
        if self.get_node(node_id) is None:
            raise ValueError(f"node not found: {node_id}")
        validate_content(content)
        seq = self._tick(time)
        self.conn.execute(
            "INSERT INTO policies(id,node_id,created_at,created_seq) "
            "VALUES(?,?,?,?)", (policy_id, node_id, float(time), seq))
        self._insert_version(policy_id, 1, time, seq, content)
        self.conn.commit()

    def _insert_version(self, policy_id, version, time, seq, content) -> None:
        self.conn.execute(
            "INSERT INTO policy_versions(policy_id,version,time,seq,content) "
            "VALUES(?,?,?,?,?)",
            (policy_id, version, float(time), seq,
             content_to_json(content)))
        self.conn.execute(
            "DELETE FROM policy_versions WHERE policy_id=? AND version<=?",
            (policy_id, version - MAX_VERSIONS))

    def _next_version(self, policy_id) -> int:
        row = self.conn.execute(
            "SELECT MAX(version) FROM policy_versions WHERE policy_id=?",
            (policy_id,)).fetchone()
        if row is None or row[0] is None:
            raise ValueError(f"policy not found: {policy_id}")
        return row[0] + 1

    def update_policy(self, policy_id, content, time) -> int:
        validate_content(content)
        seq = self._tick(time)
        version = self._next_version(policy_id)
        self._insert_version(policy_id, version, time, seq, content)
        self.conn.commit()
        return version

    def rollback_policy(self, policy_id, target_version, time) -> int:
        row = self.conn.execute(
            "SELECT content FROM policy_versions "
            "WHERE policy_id=? AND version=?",
            (policy_id, target_version)).fetchone()
        if row is None:
            raise ValueError(
                f"version {target_version} of policy {policy_id} "
                "is not retained; cannot roll back")
        content = content_from_json(row[0])
        seq = self._tick(time)
        version = self._next_version(policy_id)
        self._insert_version(policy_id, version, time, seq, content)
        self.conn.commit()
        return version

    def get_policy(self, policy_id):
        return self.conn.execute(
            "SELECT id,node_id,created_at,created_seq FROM policies "
            "WHERE id=?", (policy_id,)).fetchone()

    def policies_of_nodes(self, node_ids):
        if not node_ids:
            return []
        marks = ",".join("?" for _ in node_ids)
        return self.conn.execute(
            f"SELECT id,node_id,created_at,created_seq FROM policies "
            f"WHERE node_id IN ({marks})", tuple(node_ids)).fetchall()

    def version_at(self, policy_id, time):
        """(version, PolicyContent) in effect at `time`, or None.

        None also when the needed version was pruned; callers distinguish
        via the policy's created_at.
        """
        row = self.conn.execute(
            "SELECT version,content FROM policy_versions "
            "WHERE policy_id=? AND time<=? "
            "ORDER BY time DESC, seq DESC LIMIT 1",
            (policy_id, float(time))).fetchone()
        if row is None:
            return None
        return row[0], content_from_json(row[1])

    # -- overrides --

    def put_override(self, policy_id, node_id, kind, content, time) -> None:
        if kind not in ("set", "disable"):
            raise ValueError(f"bad override kind: {kind}")
        if kind == "set":
            if content is None:
                raise ValueError("'set' override requires content")
            validate_content(content)
        seq = self._tick(time)
        self.conn.execute(
            "INSERT INTO overrides(policy_id,node_id,time,seq,kind,content) "
            "VALUES(?,?,?,?,?,?)",
            (policy_id, node_id, float(time), seq, kind,
             content_to_json(content) if content is not None else None))
        self.conn.commit()

    def revoke_override(self, policy_id, node_id, time) -> None:
        seq = self._tick(time)
        self.conn.execute(
            "INSERT INTO overrides(policy_id,node_id,time,seq,kind,content) "
            "VALUES(?,?,?,?,?,NULL)",
            (policy_id, node_id, float(time), seq, "revoke"))
        self.conn.commit()

    def overrides_for(self, policy_ids, node_ids, time):
        """All override events for the given policies and nodes, at `time`.

        Returns rows (policy_id, node_id, time, seq, kind, content_json)
        ordered by time, seq. Kept complete forever, so replay is exact.
        """
        if not policy_ids or not node_ids:
            return []
        pm = ",".join("?" for _ in policy_ids)
        nm = ",".join("?" for _ in node_ids)
        return self.conn.execute(
            f"SELECT policy_id,node_id,time,seq,kind,content FROM overrides "
            f"WHERE policy_id IN ({pm}) AND node_id IN ({nm}) AND time<=? "
            f"ORDER BY time, seq",
            (*policy_ids, *node_ids, float(time))).fetchall()

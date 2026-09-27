"""SQLite 持久化层。

 时间点一律用 Unix 时间戳（float）存储，由调用方给出；模块不读系统时钟。
 写入时间单调不减，同时间戳时以全局写入序号 seq 区分先后（后写的为准）。
 由于写入时间单调，版本号、覆盖事件 id 与时间天然同序，"T 时刻生效"即
 "valid_from <= T 的最大版本"。
"""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    parent_id TEXT,
    name TEXT NOT NULL,
    timezone TEXT,
    level INTEGER NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(node_id),
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policies_node ON policies(node_id);
CREATE TABLE IF NOT EXISTS policy_versions (
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    valid_from REAL NOT NULL,
    seq INTEGER NOT NULL,
    content TEXT NOT NULL,
    PRIMARY KEY (policy_id, version)
);
CREATE TABLE IF NOT EXISTS override_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,           -- 'replace' | 'disable' | 'revoke'
    content TEXT,                 -- replace 时的替换内容（JSON）
    created_at REAL NOT NULL,
    seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_override_target
    ON override_events(policy_id, node_id, created_at);
"""

_KEEP_VERSIONS = 20


class Store:
    """所有读写都经过此类；模块不读系统时钟，时间点由调用方给出。"""

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ---- 写入时钟 ----

    def last_write_time(self) -> float | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'last_write_time'"
        ).fetchone()
        return None if row is None else float(row["value"])

    def advance_clock(self, t: float) -> int:
        """记录一次写入，返回本次写入的全局序号。调用方需已校验单调性。"""
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'write_seq'"
        ).fetchone()
        seq = 1 if row is None else int(row["value"]) + 1
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES ('write_seq', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(seq),),
        )
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES ('last_write_time', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (repr(t),),
        )
        return seq

    # ---- 节点 ----

    def add_node(self, node_id, parent_id, name, timezone, level, t) -> None:
        self._conn.execute(
            "INSERT INTO nodes(node_id, parent_id, name, timezone, level, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (node_id, parent_id, name, timezone, level, t),
        )

    def get_node(self, node_id) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM nodes WHERE node_id = ?", (node_id,)
        ).fetchone()

    def get_path(self, node_id) -> list[sqlite3.Row]:
        """返回从根到该节点的路径（含自身）。层级最多 3 级。"""
        path = []
        current = self.get_node(node_id)
        while current is not None:
            path.append(current)
            current = (
                self.get_node(current["parent_id"]) if current["parent_id"] else None
            )
        path.reverse()
        return path

    # ---- 策略与版本 ----

    def add_policy(self, policy_id, node_id, t) -> None:
        self._conn.execute(
            "INSERT INTO policies(policy_id, node_id, created_at) VALUES (?, ?, ?)",
            (policy_id, node_id, t),
        )

    def get_policy(self, policy_id) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM policies WHERE policy_id = ?", (policy_id,)
        ).fetchone()

    def policies_for_nodes(self, node_ids) -> list[sqlite3.Row]:
        if not node_ids:
            return []
        marks = ",".join("?" for _ in node_ids)
        return list(
            self._conn.execute(
                f"SELECT * FROM policies WHERE node_id IN ({marks})",
                tuple(node_ids),
            )
        )

    def add_version(self, policy_id, version, t, seq, content_json) -> None:
        self._conn.execute(
            "INSERT INTO policy_versions(policy_id, version, valid_from, seq, content)"
            " VALUES (?, ?, ?, ?, ?)",
            (policy_id, version, t, seq, content_json),
        )
        # 每条策略只保留最近 20 个版本
        self._conn.execute(
            "DELETE FROM policy_versions WHERE policy_id = ? AND version <= ?",
            (policy_id, version - _KEEP_VERSIONS),
        )

    def latest_version(self, policy_id) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ?"
            " ORDER BY version DESC LIMIT 1",
            (policy_id,),
        ).fetchone()

    def get_version(self, policy_id, version) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
            (policy_id, version),
        ).fetchone()

    def version_at(self, policy_id, t) -> sqlite3.Row | None:
        """t 时刻生效的版本（valid_from <= t 的最大版本；可能已被清理则返回 None）。"""
        return self._conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ? AND valid_from <= ?"
            " ORDER BY version DESC LIMIT 1",
            (policy_id, t),
        ).fetchone()

    # ---- 覆盖事件 ----

    def add_override_event(self, policy_id, node_id, kind, content_json, t, seq) -> None:
        self._conn.execute(
            "INSERT INTO override_events(policy_id, node_id, kind, content,"
            " created_at, seq) VALUES (?, ?, ?, ?, ?, ?)",
            (policy_id, node_id, kind, content_json, t, seq),
        )

    def override_events_for(self, policy_ids, node_ids, t) -> list[sqlite3.Row]:
        """t 时刻（含）之前、由 node_ids 对 policy_ids 登记的全部覆盖事件。"""
        if not policy_ids or not node_ids:
            return []
        pm = ",".join("?" for _ in policy_ids)
        nm = ",".join("?" for _ in node_ids)
        return list(
            self._conn.execute(
                f"SELECT * FROM override_events WHERE policy_id IN ({pm})"
                f" AND node_id IN ({nm}) AND created_at <= ? ORDER BY id",
                (*policy_ids, *node_ids, t),
            )
        )

    def commit(self) -> None:
        self._conn.commit()

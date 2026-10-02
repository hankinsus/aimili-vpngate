#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS servers (
    server_key TEXT PRIMARY KEY,
    hostname TEXT,
    current_ip TEXT,
    country TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_source TEXT,
    missing_count INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'NEW',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    server_key TEXT NOT NULL,
    protocol TEXT NOT NULL,
    transport TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    config_ref TEXT,
    status TEXT NOT NULL DEFAULT 'NEW',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_success REAL NOT NULL DEFAULT 0,
    last_failure REAL NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    fail_streak INTEGER NOT NULL DEFAULT 0,
    success_streak INTEGER NOT NULL DEFAULT 0,
    next_test REAL NOT NULL DEFAULT 0,
    latency_ewma REAL NOT NULL DEFAULT 0,
    jitter_ewma REAL NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(server_key) REFERENCES servers(server_key)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_sched ON endpoints(status, next_test, last_success);
CREATE INDEX IF NOT EXISTS idx_servers_seen ON servers(last_seen, state);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_key TEXT NOT NULL,
    source TEXT NOT NULL,
    seen_at REAL NOT NULL,
    ip TEXT,
    ping INTEGER NOT NULL DEFAULT 0,
    speed INTEGER NOT NULL DEFAULT 0,
    sessions INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_obs_server_time ON observations(server_key, seen_at DESC);
"""

class NodePool:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path), timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def server_key(node: dict[str, Any]) -> str:
        hostname = str(node.get("host_name") or node.get("hostname") or "").strip().lower()
        if hostname:
            return hostname
        ip = str(node.get("ip") or node.get("remote_host") or "").strip()
        return ip or str(node.get("id") or "").strip()

    @staticmethod
    def endpoint_id(server_key: str, protocol: str, transport: str, port: int) -> str:
        raw = f"{server_key}|{protocol}|{transport}|{port}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:32]

    def upsert_openvpn_snapshot(self, nodes: list[dict[str, Any]], source: str = "official_csv") -> None:
        now = time.time()
        seen_keys: set[str] = set()
        with self.lock, self._connect() as db:
            for node in nodes:
                key = self.server_key(node)
                if not key:
                    continue
                seen_keys.add(key)
                hostname = str(node.get("host_name") or "").strip()
                ip = str(node.get("ip") or node.get("remote_host") or "").strip()
                country = str(node.get("country") or node.get("country_short") or "").strip()
                meta = {
                    "owner": node.get("owner", ""),
                    "asn": node.get("asn", ""),
                    "as_name": node.get("as_name", ""),
                    "location": node.get("location", ""),
                    "ip_type": node.get("ip_type", ""),
                    "quality": node.get("quality", ""),
                }
                db.execute(
                    """
                    INSERT INTO servers(server_key, hostname, current_ip, country, first_seen, last_seen, last_source, missing_count, state, metadata_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(server_key) DO UPDATE SET
                      hostname=excluded.hostname,
                      current_ip=excluded.current_ip,
                      country=excluded.country,
                      last_seen=excluded.last_seen,
                      last_source=excluded.last_source,
                      missing_count=0,
                      state=CASE WHEN servers.state='RETIRED' THEN 'NEW' ELSE servers.state END,
                      metadata_json=excluded.metadata_json
                    """,
                    (key, hostname, ip, country, now, now, source, 0, "NEW", json.dumps(meta, ensure_ascii=False)),
                )

                protocol = "openvpn"
                transport = str(node.get("proto") or "unknown").lower()
                port = int(node.get("remote_port") or 0)
                eid = self.endpoint_id(key, protocol, transport, port)
                endpoint_meta = {
                    "node_id": node.get("id", ""),
                    "config_file": node.get("config_file", ""),
                }
                db.execute(
                    """
                    INSERT INTO endpoints(endpoint_id, server_key, protocol, transport, port, config_ref, status, first_seen, last_seen, metadata_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(endpoint_id) DO UPDATE SET
                      last_seen=excluded.last_seen,
                      config_ref=excluded.config_ref,
                      metadata_json=excluded.metadata_json,
                      status=CASE WHEN endpoints.status='RETIRED' THEN 'NEW' ELSE endpoints.status END
                    """,
                    (eid, key, protocol, transport, port, str(node.get("config_file") or ""), "NEW", now, now, json.dumps(endpoint_meta, ensure_ascii=False)),
                )

                db.execute(
                    "INSERT INTO observations(server_key, source, seen_at, ip, ping, speed, sessions, score) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        key, source, now, ip,
                        int(node.get("ping") or 0), int(node.get("speed") or 0),
                        int(node.get("sessions") or 0), int(node.get("score") or 0),
                    ),
                )

            # Missing from one partial snapshot is not death. Increment only,
            # and transition gradually after repeated absence.
            rows = db.execute("SELECT server_key, missing_count, state FROM servers").fetchall()
            for row in rows:
                if row["server_key"] in seen_keys:
                    continue
                missing = int(row["missing_count"] or 0) + 1
                state = row["state"]
                if missing >= 48 and state not in ("HOT", "AVAILABLE"):
                    state = "STALE"
                if missing >= 240 and state == "STALE":
                    state = "RETIRED"
                db.execute(
                    "UPDATE servers SET missing_count=?, state=? WHERE server_key=?",
                    (missing, state, row["server_key"]),
                )
            db.commit()

    def record_probe(self, node: dict[str, Any], ok: bool, latency_ms: int = 0, message: str = "") -> None:
        key = self.server_key(node)
        if not key:
            return
        protocol = str(node.get("protocol") or "openvpn").lower()
        transport = str(node.get("proto") or node.get("transport") or "unknown").lower()
        port = int(node.get("remote_port") or node.get("port") or 0)
        eid = self.endpoint_id(key, protocol, transport, port)
        now = time.time()

        with self.lock, self._connect() as db:
            row = db.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (eid,)).fetchone()
            if row is None:
                return

            old_latency = float(row["latency_ewma"] or 0)
            old_jitter = float(row["jitter_ewma"] or 0)
            if ok:
                latency = max(0, int(latency_ms or 0))
                latency_ewma = float(latency) if old_latency <= 0 else old_latency * 0.75 + latency * 0.25
                jitter_sample = abs(float(latency) - old_latency) if old_latency > 0 and latency > 0 else 0.0
                jitter_ewma = jitter_sample if old_jitter <= 0 else old_jitter * 0.75 + jitter_sample * 0.25
                success_count = int(row["success_count"]) + 1
                success_streak = int(row["success_streak"]) + 1
                status = "HOT" if success_streak >= 3 and jitter_ewma <= 80 else "AVAILABLE"
                db.execute(
                    """
                    UPDATE endpoints SET status=?, last_success=?, success_count=?, success_streak=?,
                    fail_streak=0, next_test=?, latency_ewma=?, jitter_ewma=? WHERE endpoint_id=?
                    """,
                    (status, now, success_count, success_streak, now + 60, latency_ewma, jitter_ewma, eid),
                )
                db.execute("UPDATE servers SET state=?, last_seen=? WHERE server_key=?", (status, now, key))
            else:
                failure_count = int(row["failure_count"]) + 1
                fail_streak = int(row["fail_streak"]) + 1
                backoff = min(7200, 30 * (4 ** min(fail_streak - 1, 4)))
                status = "DEGRADED" if fail_streak < 3 else "COOLDOWN"
                db.execute(
                    """
                    UPDATE endpoints SET status=?, last_failure=?, failure_count=?, fail_streak=?,
                    success_streak=0, next_test=?, metadata_json=? WHERE endpoint_id=?
                    """,
                    (
                        status, now, failure_count, fail_streak, now + backoff,
                        json.dumps({"last_error": message}, ensure_ascii=False), eid,
                    ),
                )
                db.execute("UPDATE servers SET state=? WHERE server_key=?", (status, key))
            db.commit()

    def stats(self) -> dict[str, Any]:
        with self.lock, self._connect() as db:
            servers = db.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"]
            endpoints = db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"]
            states = {
                row["state"]: row["c"]
                for row in db.execute("SELECT state, COUNT(*) c FROM servers GROUP BY state").fetchall()
            }
            return {"servers": servers, "endpoints": endpoints, "states": states}

#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import time
from contextlib import closing
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
        with closing(self._connect()) as db:
            db.executescript(_SCHEMA)
            db.commit()

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

    def upsert_discovery_snapshot(self, servers: list[dict[str, Any]], source: str = "official_html") -> None:
        now = time.time()
        seen_keys: set[str] = set()
        with self.lock, closing(self._connect()) as db:
            for server in servers:
                hostname = str(server.get("hostname") or server.get("host_name") or "").strip().lower()
                ip = str(server.get("ip") or "").strip()
                key = hostname or ip
                if not key:
                    continue
                seen_keys.add(key)
                country = str(server.get("country") or "").strip()
                metadata = {
                    "source": source,
                    "ping": int(server.get("ping") or 0),
                    "speed": int(server.get("speed") or 0),
                    "sessions": int(server.get("sessions") or 0),
                    "score": int(server.get("score") or 0),
                    "source_count": int(server.get("source_count") or 0),
                    "trusted_observation": bool(server.get("trusted_observation")),
                    "sources": list(server.get("_sources") or []),
                }
                existing_server = db.execute(
                    "SELECT metadata_json FROM servers WHERE server_key=?",
                    (key,),
                ).fetchone()
                if existing_server:
                    try:
                        previous_meta = json.loads(existing_server["metadata_json"] or "{}")
                        if isinstance(previous_meta, dict):
                            previous_meta.update({k: v for k, v in metadata.items() if v not in (None, "")})
                            metadata = previous_meta
                    except Exception:
                        pass
                db.execute(
                    """
                    INSERT INTO servers(server_key, hostname, current_ip, country, first_seen, last_seen, last_source, missing_count, state, metadata_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(server_key) DO UPDATE SET
                      hostname=CASE WHEN excluded.hostname<>'' THEN excluded.hostname ELSE servers.hostname END,
                      current_ip=CASE WHEN excluded.current_ip<>'' THEN excluded.current_ip ELSE servers.current_ip END,
                      country=CASE WHEN excluded.country<>'' THEN excluded.country ELSE servers.country END,
                      last_seen=excluded.last_seen,
                      last_source=excluded.last_source,
                      missing_count=0,
                      state=CASE WHEN servers.state IN ('RETIRED','STALE') THEN 'NEW' ELSE servers.state END,
                      metadata_json=excluded.metadata_json
                    """,
                    (key, hostname, ip, country, now, now, source, 0, "NEW", json.dumps(metadata, ensure_ascii=False)),
                )

                for endpoint in server.get("protocols") or []:
                    protocol = str(endpoint.get("protocol") or "").strip().lower()
                    transport = str(endpoint.get("transport") or "unknown").strip().lower()
                    try:
                        port = int(endpoint.get("port") or 0)
                    except (TypeError, ValueError):
                        port = 0
                    if not protocol:
                        continue
                    eid = self.endpoint_id(key, protocol, transport, port)
                    endpoint_meta = {
                        "hostname": str(endpoint.get("hostname") or hostname or "").strip().lower(),
                        "ip": ip,
                        "source": source,
                        "source_count": int(server.get("source_count") or 0),
                        "trusted_observation": bool(server.get("trusted_observation")),
                    }
                    existing_endpoint = db.execute(
                        "SELECT metadata_json FROM endpoints WHERE endpoint_id=?",
                        (eid,),
                    ).fetchone()
                    if existing_endpoint:
                        try:
                            previous_endpoint_meta = json.loads(existing_endpoint["metadata_json"] or "{}")
                            if isinstance(previous_endpoint_meta, dict):
                                previous_endpoint_meta.update({k: v for k, v in endpoint_meta.items() if v not in (None, "")})
                                endpoint_meta = previous_endpoint_meta
                        except Exception:
                            pass
                    db.execute(
                        """
                        INSERT INTO endpoints(endpoint_id, server_key, protocol, transport, port, status, first_seen, last_seen, metadata_json)
                        VALUES(?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(endpoint_id) DO UPDATE SET
                          last_seen=excluded.last_seen,
                          metadata_json=excluded.metadata_json,
                          status=CASE WHEN endpoints.status IN ('RETIRED','STALE') THEN 'NEW' ELSE endpoints.status END
                        """,
                        (eid, key, protocol, transport, port, "NEW", now, now, json.dumps(endpoint_meta, ensure_ascii=False)),
                    )

                db.execute(
                    "INSERT INTO observations(server_key, source, seen_at, ip, ping, speed, sessions, score) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        key, source, now, ip,
                        int(server.get("ping") or 0), int(server.get("speed") or 0),
                        int(server.get("sessions") or 0), int(server.get("score") or 0),
                    ),
                )

            # The HTML list is explicitly partial, so absence in this snapshot
            # must not aggressively age every historical server. Only endpoints
            # that remain unseen for long periods are naturally deprioritized by
            # next_test / last_seen scheduling.
            db.commit()

    def list_endpoints(self, protocol: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self.lock, closing(self._connect()) as db:
            params: list[Any] = []
            where = ""
            if protocol:
                where = "WHERE e.protocol=?"
                params.append(str(protocol).lower())
            params.append(limit)
            rows = db.execute(
                f"""
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_ping,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_sessions,
                       COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_server_score
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                {where}
                ORDER BY
                  CASE e.status
                    WHEN 'HOT' THEN 0
                    WHEN 'AVAILABLE' THEN 1
                    WHEN 'NEW' THEN 2
                    WHEN 'DEGRADED' THEN 3
                    WHEN 'COOLDOWN' THEN 4
                    WHEN 'STALE' THEN 5
                    ELSE 6
                  END,
                  e.next_test ASC,
                  e.latency_ewma ASC,
                  e.last_seen DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                try:
                    item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
                except Exception:
                    item["metadata"] = {}
                    item.pop("metadata_json", None)
                try:
                    item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
                except Exception:
                    item["server_metadata"] = {}
                    item.pop("server_metadata_json", None)
                result.append(item)
            return result

    def upsert_openvpn_snapshot(self, nodes: list[dict[str, Any]], source: str = "official_csv") -> None:
        now = time.time()
        seen_keys: set[str] = set()
        with self.lock, closing(self._connect()) as db:
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
                existing_server = db.execute(
                    "SELECT metadata_json FROM servers WHERE server_key=?",
                    (key,),
                ).fetchone()
                if existing_server:
                    try:
                        previous_meta = json.loads(existing_server["metadata_json"] or "{}")
                        if isinstance(previous_meta, dict):
                            previous_meta.update({k: v for k, v in meta.items() if v not in (None, "")})
                            meta = previous_meta
                    except Exception:
                        pass
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
                      state=CASE WHEN servers.state IN ('RETIRED','STALE') THEN 'NEW' ELSE servers.state END,
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
                    "trusted_observation": True,
                    "source_count": 1,
                }
                existing_endpoint = db.execute(
                    "SELECT metadata_json FROM endpoints WHERE endpoint_id=?",
                    (eid,),
                ).fetchone()
                if existing_endpoint:
                    try:
                        previous_endpoint_meta = json.loads(existing_endpoint["metadata_json"] or "{}")
                        if isinstance(previous_endpoint_meta, dict):
                            previous_endpoint_meta.update({k: v for k, v in endpoint_meta.items() if v not in (None, "")})
                            endpoint_meta = previous_endpoint_meta
                    except Exception:
                        pass
                db.execute(
                    """
                    INSERT INTO endpoints(endpoint_id, server_key, protocol, transport, port, config_ref, status, first_seen, last_seen, metadata_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(endpoint_id) DO UPDATE SET
                      last_seen=excluded.last_seen,
                      config_ref=excluded.config_ref,
                      metadata_json=excluded.metadata_json,
                      status=CASE WHEN endpoints.status IN ('RETIRED','STALE') THEN 'NEW' ELSE endpoints.status END
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

        with self.lock, closing(self._connect()) as db:
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
                    (status, now, success_count, success_streak, now + 900, latency_ewma, jitter_ewma, eid),
                )
                db.execute("UPDATE servers SET state=?, last_seen=? WHERE server_key=?", (status, now, key))
            else:
                failure_count = int(row["failure_count"]) + 1
                fail_streak = int(row["fail_streak"]) + 1
                backoff = min(7200, 30 * (4 ** min(fail_streak - 1, 4)))
                status = "DEGRADED" if fail_streak < 3 else "COOLDOWN"
                try:
                    endpoint_meta = json.loads(row["metadata_json"] or "{}")
                    if not isinstance(endpoint_meta, dict):
                        endpoint_meta = {}
                except Exception:
                    endpoint_meta = {}
                endpoint_meta["last_error"] = message
                db.execute(
                    """
                    UPDATE endpoints SET status=?, last_failure=?, failure_count=?, fail_streak=?,
                    success_streak=0, next_test=?, metadata_json=? WHERE endpoint_id=?
                    """,
                    (
                        status, now, failure_count, fail_streak, now + backoff,
                        json.dumps(endpoint_meta, ensure_ascii=False), eid,
                    ),
                )
                db.execute("UPDATE servers SET state=? WHERE server_key=?", (status, key))
            db.commit()

    @staticmethod
    def _selection_score(endpoint: dict[str, Any], now: float | None = None) -> tuple[float, dict[str, float]]:
        now = time.time() if now is None else now
        status = str(endpoint.get("status") or "")
        success = max(0, int(endpoint.get("success_count") or 0))
        failure = max(0, int(endpoint.get("failure_count") or 0))
        total = success + failure
        reliability = (success + 3.0) / (total + 4.0)
        success_streak = max(0, int(endpoint.get("success_streak") or 0))
        fail_streak = max(0, int(endpoint.get("fail_streak") or 0))
        latency = float(endpoint.get("latency_ewma") or 0)
        jitter = float(endpoint.get("jitter_ewma") or 0)
        last_success = float(endpoint.get("last_success") or 0)
        age = max(0.0, now - last_success) if last_success > 0 else 86400.0

        speed_bps = max(0, int(endpoint.get("latest_speed") or 0))
        speed_mbps = speed_bps / 1_000_000.0
        sessions = max(0, int(endpoint.get("latest_sessions") or 0))
        server_score = max(0, int(endpoint.get("latest_server_score") or 0))

        status_bonus = 500.0 if status == "HOT" else 350.0 if status == "AVAILABLE" else 0.0
        reliability_bonus = reliability * 650.0
        streak_bonus = min(success_streak, 10) * 22.0
        freshness_bonus = max(0.0, 80.0 - age / 60.0)
        speed_bonus = min(100.0, math.log10(max(1.0, speed_mbps)) * 35.0) if speed_mbps > 0 else 0.0
        server_score_bonus = min(60.0, math.log10(max(1.0, float(server_score))) * 12.0) if server_score > 0 else 0.0

        latency_penalty = min(900.0, latency if latency > 0 else 700.0) * 0.75
        jitter_penalty = min(400.0, jitter) * 1.5
        fail_penalty = fail_streak * 140.0
        load_penalty = min(250, sessions) * 0.45

        final = (
            status_bonus
            + reliability_bonus
            + streak_bonus
            + freshness_bonus
            + speed_bonus
            + server_score_bonus
            - latency_penalty
            - jitter_penalty
            - fail_penalty
            - load_penalty
        )
        details = {
            "status_bonus": round(status_bonus, 2),
            "reliability": round(reliability, 4),
            "reliability_bonus": round(reliability_bonus, 2),
            "streak_bonus": round(streak_bonus, 2),
            "freshness_bonus": round(freshness_bonus, 2),
            "speed_bonus": round(speed_bonus, 2),
            "server_score_bonus": round(server_score_bonus, 2),
            "latency_penalty": round(latency_penalty, 2),
            "jitter_penalty": round(jitter_penalty, 2),
            "fail_penalty": round(fail_penalty, 2),
            "load_penalty": round(load_penalty, 2),
        }
        return final, details

    def age_lifecycle(
        self,
        stale_after_seconds: int = 6 * 3600,
        retire_after_seconds: int = 72 * 3600,
    ) -> dict[str, int]:
        now = time.time()
        stale_cutoff = now - max(3600, int(stale_after_seconds))
        retire_cutoff = now - max(int(stale_after_seconds) + 3600, int(retire_after_seconds))
        with self.lock, closing(self._connect()) as db:
            retired = db.execute(
                """
                UPDATE endpoints
                SET status='RETIRED'
                WHERE status NOT IN ('RETIRED')
                  AND last_seen < ?
                  AND (last_success=0 OR last_success < ?)
                """,
                (retire_cutoff, retire_cutoff),
            ).rowcount
            stale = db.execute(
                """
                UPDATE endpoints
                SET status='STALE'
                WHERE status IN ('HOT','AVAILABLE','NEW','DEGRADED','COOLDOWN')
                  AND last_seen < ?
                  AND (last_success=0 OR last_success < ?)
                """,
                (stale_cutoff, stale_cutoff),
            ).rowcount
            db.execute(
                """
                UPDATE servers
                SET state='RETIRED'
                WHERE state <> 'RETIRED'
                  AND last_seen < ?
                  AND server_key NOT IN (
                    SELECT server_key FROM endpoints WHERE status NOT IN ('RETIRED')
                  )
                """,
                (retire_cutoff,),
            )
            db.execute(
                """
                UPDATE servers
                SET state='STALE'
                WHERE state NOT IN ('RETIRED','STALE')
                  AND last_seen < ?
                  AND server_key NOT IN (
                    SELECT server_key FROM endpoints WHERE status IN ('HOT','AVAILABLE')
                  )
                """,
                (stale_cutoff,),
            )
            db.commit()
            return {"stale_endpoints": int(stale or 0), "retired_endpoints": int(retired or 0)}

    def ranked_hot_pool(
        self,
        limit: int = 10,
        protocols: tuple[str, ...] = ("openvpn", "softether", "sstp", "l2tp-ipsec"),
        per_server_limit: int = 2,
    ) -> list[dict[str, Any]]:
        self.age_lifecycle()
        protocol_set = {str(p).lower() for p in protocols}
        candidates = [
            ep for ep in self.list_endpoints(limit=1000)
            if str(ep.get("protocol") or "").lower() in protocol_set
            and ep.get("status") in ("HOT", "AVAILABLE")
            and (
                str(ep.get("protocol") or "").lower() == "openvpn"
                or bool((ep.get("metadata") or {}).get("trusted_observation"))
            )
        ]
        now = time.time()
        for endpoint in candidates:
            score, details = self._selection_score(endpoint, now)
            endpoint["selection_score"] = round(score, 2)
            endpoint["score_details"] = details
        candidates.sort(
            key=lambda ep: (
                -float(ep.get("selection_score") or -999999),
                float(ep.get("latency_ewma") or 999999),
                float(ep.get("jitter_ewma") or 999999),
                -float(ep.get("last_success") or 0),
            )
        )

        selected: list[dict[str, Any]] = []
        per_server: dict[str, int] = {}
        for endpoint in candidates:
            key = str(endpoint.get("server_key") or "")
            if per_server.get(key, 0) >= max(1, int(per_server_limit)):
                continue
            selected.append(endpoint)
            per_server[key] = per_server.get(key, 0) + 1
            if len(selected) >= max(1, min(int(limit), 50)):
                break
        return selected

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        with self.lock, closing(self._connect()) as db:
            row = db.execute(
                """
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_ping,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_sessions,
                       COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_server_score
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                WHERE e.endpoint_id=?
                """,
                (str(endpoint_id),),
            ).fetchone()
            if row is None:
                return None
            item = dict(row)
            try:
                item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            except Exception:
                item["metadata"] = {}
                item.pop("metadata_json", None)
            try:
                item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
            except Exception:
                item["server_metadata"] = {}
                item.pop("server_metadata_json", None)
            return item

    def record_endpoint_probe(self, endpoint_id: str, ok: bool, latency_ms: int = 0, message: str = "") -> None:
        now = time.time()
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (str(endpoint_id),)).fetchone()
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
                    (status, now, success_count, success_streak, now + 900, latency_ewma, jitter_ewma, endpoint_id),
                )
                db.execute("UPDATE servers SET state=?, last_seen=? WHERE server_key=?", (status, now, row["server_key"]))
            else:
                failure_count = int(row["failure_count"]) + 1
                fail_streak = int(row["fail_streak"]) + 1
                backoff = min(7200, 30 * (4 ** min(fail_streak - 1, 4)))
                status = "DEGRADED" if fail_streak < 3 else "COOLDOWN"
                try:
                    meta = json.loads(row["metadata_json"] or "{}")
                    if not isinstance(meta, dict):
                        meta = {}
                except Exception:
                    meta = {}
                meta["last_error"] = message
                db.execute(
                    """
                    UPDATE endpoints SET status=?, last_failure=?, failure_count=?, fail_streak=?,
                    success_streak=0, next_test=?, metadata_json=? WHERE endpoint_id=?
                    """,
                    (
                        status, now, failure_count, fail_streak, now + backoff,
                        json.dumps(meta, ensure_ascii=False), endpoint_id,
                    ),
                )
                db.execute("UPDATE servers SET state=? WHERE server_key=?", (status, row["server_key"]))
            db.commit()

    def due_endpoints(self, protocols: tuple[str, ...] = ("softether", "sstp"), limit: int = 20) -> list[dict[str, Any]]:
        now = time.time()
        wanted = tuple(str(p).lower() for p in protocols if p)
        if not wanted:
            return []
        placeholders = ",".join("?" for _ in wanted)
        requested_limit = max(1, min(int(limit), 200))
        fetch_limit = min(1000, max(50, requested_limit * 8))
        params: list[Any] = [*wanted, now, fetch_limit]
        with self.lock, closing(self._connect()) as db:
            # Protocol-deficit scheduling prevents one protocol (usually the
            # largest source, e.g. SoftEther) from monopolizing the warmup queue.
            counts = {
                protocol: int(
                    db.execute(
                        "SELECT COUNT(*) FROM endpoints WHERE protocol=? AND status IN ('HOT','AVAILABLE')",
                        (protocol,),
                    ).fetchone()[0]
                    or 0
                )
                for protocol in wanted
            }
            deficit = {protocol: 1.0 / max(1, counts[protocol]) for protocol in wanted}

            rows = db.execute(
                f"""
                SELECT e.endpoint_id
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                WHERE e.protocol IN ({placeholders})
                  AND e.next_test <= ?
                  AND e.status NOT IN ('RETIRED')
                ORDER BY
                  CASE e.protocol
                    {" ".join(
                        f"WHEN '{protocol}' THEN {deficit[protocol]:.12f}"
                        for protocol in wanted
                    )}
                    ELSE 0
                  END DESC,
                  e.next_test ASC,
                  CASE e.status
                    WHEN 'NEW' THEN 0
                    WHEN 'HOT' THEN 1
                    WHEN 'AVAILABLE' THEN 2
                    WHEN 'DEGRADED' THEN 3
                    WHEN 'COOLDOWN' THEN 4
                    ELSE 5
                  END,
                  e.last_seen DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            endpoint = self.get_endpoint(row["endpoint_id"])
            if not endpoint:
                continue
            metadata = endpoint.get("metadata") or {}
            if endpoint.get("protocol") != "openvpn" and not metadata.get("trusted_observation"):
                continue
            result.append(endpoint)
            if len(result) >= requested_limit:
                break
        return result

    def stats(self) -> dict[str, Any]:
        with self.lock, closing(self._connect()) as db:
            servers = db.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"]
            endpoints = db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"]
            states = {
                row["state"]: row["c"]
                for row in db.execute("SELECT state, COUNT(*) c FROM servers GROUP BY state").fetchall()
            }
            return {"servers": servers, "endpoints": endpoints, "states": states}

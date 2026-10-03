#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.cookiejar
import json
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} is not a JSON object")
    return data


class SidecarAPI:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def request(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        timeout: float = 60.0,
    ) -> Any:
        body = None
        headers: dict[str, str] = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(req, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            raise RuntimeError(
                f"HTTP {exc.code}: {raw.decode('utf-8', errors='replace')}"
            ) from exc
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def login(self) -> None:
        result = self.request(
            "/api/login",
            method="POST",
            payload={"username": self.username, "password": self.password},
            timeout=10,
        )
        if not result.get("ok"):
            raise RuntimeError(f"Sidecar login failed: {result}")


def proxy_business_probe(port: int, timeout: float = 4.0) -> tuple[bool, str]:
    cmd = [
        "curl", "-4", "-k", "-sS",
        "--proxy", f"socks5h://127.0.0.1:{int(port)}",
        "--connect-timeout", "2",
        "--max-time", str(max(2, int(timeout))),
        "https://1.1.1.1/cdn-cgi/trace",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
    except Exception as exc:
        return False, str(exc)
    if res.returncode != 0:
        return False, (res.stderr or f"curl exit {res.returncode}")[-300:]
    exit_ip = ""
    for line in res.stdout.splitlines():
        if line.startswith("ip="):
            exit_ip = line.split("=", 1)[1].strip()
            break
    return bool(exit_ip), exit_ip or "missing ip= in trace"


def wait_for_active(
    state_path: Path,
    timeout: float,
    *,
    protocol_not: str = "",
    endpoint_not: str = "",
) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = load_json(state_path)
        protocol = str(state.get("active_tunnel_protocol") or "")
        endpoint = str(state.get("active_pool_endpoint_id") or "")
        if (
            state.get("proxy_ok")
            and protocol
            and (not protocol_not or protocol != protocol_not)
            and (not endpoint_not or endpoint != endpoint_not)
        ):
            return state
        time.sleep(0.5)
    raise TimeoutError("Timed out waiting for a healthy replacement tunnel")


def summarize_samples(samples: list[dict[str, Any]], event_at: float, recovered_at: float) -> dict[str, Any]:
    window = [s for s in samples if event_at - 2 <= s["ts"] <= recovered_at + 2]
    failures = [s for s in window if not s["ok"]]
    longest = 0.0
    first_failure = None
    last_failure = None
    for sample in failures:
        if first_failure is None:
            first_failure = sample["ts"]
        last_failure = sample["ts"]
    if first_failure is not None and last_failure is not None:
        longest = max(0.0, last_failure - first_failure + 1.0)
    return {
        "samples": len(window),
        "failed_samples": len(failures),
        "observed_business_outage_seconds": round(longest, 2),
        "first_failure_offset_seconds": (
            round(first_failure - event_at, 2) if first_failure is not None else None
        ),
        "last_failure_offset_seconds": (
            round(last_failure - event_at, 2) if last_failure is not None else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AimiliVPN isolated failover stability test")
    parser.add_argument("--data-dir", default="/opt/aimilivpn-multiprotocol-test/sidecar")
    parser.add_argument("--start-endpoint", required=True)
    parser.add_argument("--failures", type=int, default=2)
    parser.add_argument("--wait-timeout", type=int, default=45)
    parser.add_argument("--sample-interval", type=float, default=1.0)
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    ui = load_json(data_dir / "ui_auth.json")
    state_path = data_dir / "state.json"
    state = load_json(state_path)
    if not state.get("isolated_instance"):
        raise SystemExit("Refusing to run: target manager is not an isolated instance")
    if not state.get("proxy_health_loop_enabled"):
        raise SystemExit("Refusing to run: proxy health loop is not enabled")

    secret = str(ui.get("secret_path") or "").strip()
    base_url = f"http://127.0.0.1:{int(ui['port'])}/{secret}"
    api = SidecarAPI(base_url, str(ui["username"]), str(ui["password"]))
    api.login()

    proxy_port = int(ui["proxy_port"])
    report: dict[str, Any] = {
        "started_at": time.time(),
        "start_endpoint": args.start_endpoint,
        "events": [],
    }

    print(f"[1] Connecting start endpoint {args.start_endpoint}", flush=True)
    connected = api.request(
        "/api/connect_pool_endpoint",
        method="POST",
        payload={"endpoint_id": args.start_endpoint},
        timeout=60,
    )
    if not connected.get("ok"):
        raise RuntimeError(f"Initial connection failed: {connected}")
    state = load_json(state_path)
    print(
        f"    active={state.get('active_tunnel_protocol')} "
        f"{state.get('active_pool_endpoint_id')} "
        f"ip={state.get('proxy_ip')} latency={state.get('proxy_latency_ms')}ms",
        flush=True,
    )

    samples: list[dict[str, Any]] = []
    stop_event = threading.Event()

    def watcher() -> None:
        while not stop_event.is_set():
            started = time.time()
            ok, info = proxy_business_probe(proxy_port)
            samples.append({"ts": time.time(), "ok": ok, "info": info})
            spent = time.time() - started
            stop_event.wait(max(0.05, args.sample_interval - spent))

    thread = threading.Thread(target=watcher, daemon=True)
    thread.start()
    time.sleep(3)

    try:
        for index in range(max(1, args.failures)):
            before = load_json(state_path)
            from_protocol = str(before.get("active_tunnel_protocol") or "")
            from_endpoint = str(before.get("active_pool_endpoint_id") or "")
            print(
                f"[{index + 2}] Simulating failure: {from_protocol} {from_endpoint}",
                flush=True,
            )
            event_at = time.time()
            result = api.request(
                "/api/simulate_tunnel_failure",
                method="POST",
                payload={},
                timeout=10,
            )
            if not result.get("ok"):
                raise RuntimeError(f"Failure simulation rejected: {result}")

            recovered = wait_for_active(
                state_path,
                args.wait_timeout,
                protocol_not=from_protocol,
                endpoint_not=from_endpoint,
            )
            recovered_at = time.time()
            time.sleep(2)
            event = {
                "from_protocol": from_protocol,
                "from_endpoint": from_endpoint,
                "to_protocol": recovered.get("active_tunnel_protocol"),
                "to_endpoint": recovered.get("active_pool_endpoint_id"),
                "to_ip": recovered.get("proxy_ip"),
                "to_latency_ms": recovered.get("proxy_latency_ms"),
                "wall_recovery_seconds": round(recovered_at - event_at, 2),
                "manager_failover_duration_ms": recovered.get("last_failover_duration_ms"),
                "manager_failover_ok": recovered.get("last_failover_ok"),
            }
            event.update(summarize_samples(samples, event_at, recovered_at))
            report["events"].append(event)
            print("    " + json.dumps(event, ensure_ascii=False), flush=True)

        report["finished_at"] = time.time()
        report["final_state"] = {
            "protocol": load_json(state_path).get("active_tunnel_protocol"),
            "endpoint": load_json(state_path).get("active_pool_endpoint_id"),
            "ip": load_json(state_path).get("proxy_ip"),
        }
    finally:
        stop_event.set()
        thread.join(timeout=3)
        try:
            api.request("/api/disconnect", method="POST", payload={}, timeout=20)
        except Exception as exc:
            report["disconnect_error"] = str(exc)

    report_path = data_dir / f"stability-report-{int(time.time())}.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[DONE] {report_path}", flush=True)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

@dataclass
class TunnelResult:
    ok: bool
    protocol: str
    interface: str = ""
    message: str = ""
    process: subprocess.Popen[str] | None = None

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def list_interfaces() -> set[str]:
    try:
        return {p.name for p in Path("/sys/class/net").iterdir()}
    except Exception:
        return set()

def wait_for_new_interface(before: set[str], prefixes: tuple[str, ...], timeout: float = 15.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = list_interfaces()
        candidates = sorted(
            iface for iface in current - before
            if iface.startswith(prefixes)
        )
        if candidates:
            return candidates[0]
        # A client may reuse an already-created adapter.
        reused = sorted(iface for iface in current if iface.startswith(prefixes))
        if reused:
            return reused[0]
        time.sleep(0.5)
    return ""

def interface_has_ipv4(iface: str) -> bool:
    if not iface:
        return False
    try:
        res = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=3,
        )
        return res.returncode == 0 and " inet " in f" {res.stdout} "
    except Exception:
        return False

def obtain_dhcp(iface: str, timeout: int = 12) -> bool:
    if not iface:
        return False
    clients = [
        ["dhclient", "-1", "-v", iface],
        ["udhcpc", "-n", "-q", "-i", iface],
    ]
    for cmd in clients:
        if not command_exists(cmd[0]):
            continue
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0 and interface_has_ipv4(iface):
                return True
        except Exception:
            pass
    return interface_has_ipv4(iface)

class SoftEtherAdapter:
    protocol = "softether"

    @staticmethod
    def available() -> bool:
        return command_exists("vpnclient") and command_exists("vpncmd")

    @staticmethod
    def _vpncmd(*args: str, timeout: int = 12) -> subprocess.CompletedProcess[str]:
        cmd = ["vpncmd", "localhost", "/CLIENT", "/CMD", *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def connect(self, host: str, port: int = 443, account: str = "aimili", nic: str = "aimili") -> TunnelResult:
        if not self.available():
            return TunnelResult(False, self.protocol, message="vpnclient/vpncmd not installed")
        before = list_interfaces()
        try:
            subprocess.run(["vpnclient", "start"], capture_output=True, text=True, timeout=8)
            # Idempotent cleanup. These commands may fail when entries do not exist.
            self._vpncmd("AccountDisconnect", account, timeout=5)
            self._vpncmd("AccountDelete", account, timeout=5)
            self._vpncmd("NicCreate", nic, timeout=8)

            created = self._vpncmd(
                "AccountCreate", account,
                f"/SERVER:{host}:{int(port)}",
                "/HUB:VPNGATE",
                "/USERNAME:vpn",
                f"/NICNAME:{nic}",
                timeout=10,
            )
            if created.returncode != 0:
                return TunnelResult(False, self.protocol, message=(created.stdout + created.stderr)[-1200:])
            self._vpncmd("AccountAnonymousSet", account, timeout=6)
            connected = self._vpncmd("AccountConnect", account, timeout=10)
            if connected.returncode != 0:
                return TunnelResult(False, self.protocol, message=(connected.stdout + connected.stderr)[-1200:])

            iface = wait_for_new_interface(before, ("vpn_",), timeout=12)
            if not iface:
                iface = f"vpn_{nic}"
            if not obtain_dhcp(iface):
                self.disconnect(account)
                return TunnelResult(False, self.protocol, interface=iface, message="SoftEther connected but DHCP/IP assignment failed")
            return TunnelResult(True, self.protocol, interface=iface, message="SoftEther connected")
        except Exception as exc:
            return TunnelResult(False, self.protocol, message=str(exc))

    def disconnect(self, account: str = "aimili") -> None:
        if not self.available():
            return
        try:
            self._vpncmd("AccountDisconnect", account, timeout=6)
        except Exception:
            pass

class SSTPAdapter:
    protocol = "sstp"

    @staticmethod
    def available() -> bool:
        return command_exists("sstpc") and command_exists("pppd")

    def connect(self, hostname: str, username: str = "vpn", password: str = "vpn", timeout: int = 20) -> TunnelResult:
        if not self.available():
            return TunnelResult(False, self.protocol, message="sstpc/pppd not installed")
        before = list_interfaces()
        # VPNGate requires the DDNS hostname for SSTP/TLS identity. Do not
        # silently replace it with the current IP address.
        if not hostname or "." not in hostname:
            return TunnelResult(False, self.protocol, message="SSTP requires a valid VPNGate hostname")
        cmd = [
            "sstpc",
            "--user", username,
            "--password", password,
            "--save-server-route",
            hostname,
            "usepeerdns",
            "require-mschap-v2",
            "noauth",
            "refuse-eap",
            "noipdefault",
            "nodefaultroute",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            iface = wait_for_new_interface(before, ("ppp",), timeout=float(timeout))
            if not iface or proc.poll() is not None:
                output = ""
                try:
                    output = (proc.stdout.read() if proc.stdout else "")[-1200:]
                except Exception:
                    pass
                if proc.poll() is None:
                    proc.terminate()
                return TunnelResult(False, self.protocol, message=output or "SSTP PPP interface was not created", process=proc)
            if not interface_has_ipv4(iface):
                time.sleep(2)
            if not interface_has_ipv4(iface):
                proc.terminate()
                return TunnelResult(False, self.protocol, interface=iface, message="SSTP interface has no IPv4 address", process=proc)
            return TunnelResult(True, self.protocol, interface=iface, message="SSTP connected", process=proc)
        except Exception as exc:
            return TunnelResult(False, self.protocol, message=str(exc))

    @staticmethod
    def disconnect(process: subprocess.Popen[str] | None) -> None:
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()

class L2TPIPsecAdapter:
    protocol = "l2tp-ipsec"

    @staticmethod
    def available() -> bool:
        # Connection activation is intentionally not enabled yet. L2TP/IPsec
        # changes XFRM/IPsec state globally and will be moved into a dedicated
        # network namespace before production use.
        return (
            command_exists("ipsec")
            and command_exists("xl2tpd")
            and command_exists("pppd")
        )

    def connect(self, *args: Any, **kwargs: Any) -> TunnelResult:
        return TunnelResult(
            False,
            self.protocol,
            message="L2TP/IPsec adapter installed but activation is gated until network-namespace isolation is enabled",
        )

def capability_report() -> dict[str, Any]:
    return {
        "openvpn": {"installed": command_exists("openvpn"), "activation": "enabled"},
        "softether": {"installed": SoftEtherAdapter.available(), "activation": "development"},
        "sstp": {"installed": SSTPAdapter.available(), "activation": "development"},
        "l2tp_ipsec": {"installed": L2TPIPsecAdapter.available(), "activation": "gated-netns"},
    }

#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
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
    gateway: str = ""
    namespace: str = ""
    inner_interface: str = ""
    work_dir: str = ""
    details: dict[str, Any] | None = None

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

def snapshot_main_routes() -> set[str]:
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "table", "main"],
            capture_output=True, text=True, timeout=3,
        )
        return {line.strip() for line in res.stdout.splitlines() if line.strip()}
    except Exception:
        return set()

def _is_cleanup_host_route(line: str) -> bool:
    parts = str(line or "").split()
    if not parts or parts[0] == "default":
        return False
    target = parts[0]
    try:
        network = ipaddress.ip_network(target if "/" in target else target + "/32", strict=False)
    except ValueError:
        return False
    if network.version != 4 or network.prefixlen != 32:
        return False
    # Never remove routes owned by a VPN interface itself. We only clean the
    # physical-interface host routes SoftEther may add to preserve server reachability.
    joined = " ".join(parts)
    if any(marker in joined for marker in (" dev vpn_", " dev tun", " dev ppp", " dev alh", " dev aln")):
        return False
    return True

def added_cleanup_host_routes(before: set[str]) -> list[str]:
    current = snapshot_main_routes()
    return sorted(line for line in current - before if _is_cleanup_host_route(line))

def cleanup_route_lines(routes: list[str] | tuple[str, ...] | set[str] | None) -> None:
    for line in routes or []:
        if not _is_cleanup_host_route(str(line)):
            continue
        try:
            subprocess.run(
                ["ip", "route", "del", *str(line).split()],
                capture_output=True, text=True, timeout=3,
            )
        except Exception:
            pass

def obtain_dhcp_lease(iface: str, timeout: int = 15) -> tuple[bool, str, str]:
    """Acquire a DHCP lease without installing a system default route.

    The DHCP hook configures only the interface address/link and records the
    offered gateway. Policy routing is added later by the tunnel manager.
    """
    if not iface:
        return False, "", "missing interface"

    work_dir = Path(tempfile.mkdtemp(prefix="aimili-dhcp-"))
    lease_file = work_dir / "lease.json"
    hook = work_dir / "dhcp-hook.py"
    hook.write_text(
        """#!/usr/bin/env python3
import ipaddress
import json
import os
import pathlib
import subprocess
import sys

event = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("reason", "")).lower()
iface = os.environ.get("interface", "")
if not iface:
    sys.exit(0)

if event in ("deconfig", "expire", "fail", "release", "stop"):
    subprocess.run(["ip", "addr", "flush", "dev", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.exit(0)

if event not in ("bound", "renew", "rebind", "reboot"):
    sys.exit(0)

ip = os.environ.get("ip") or os.environ.get("new_ip_address") or ""
mask = os.environ.get("subnet") or os.environ.get("new_subnet_mask") or "255.255.255.0"
routers = os.environ.get("router") or os.environ.get("new_routers") or ""
gateway = routers.split()[0] if routers.split() else ""
if not ip:
    sys.exit(1)

prefix = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
subprocess.run(["ip", "addr", "flush", "dev", iface], check=True)
subprocess.run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface], check=True)
subprocess.run(["ip", "link", "set", iface, "up"], check=True)
pathlib.Path("/PLACEHOLDER").write_text(
    json.dumps({"ip": ip, "prefix": prefix, "gateway": gateway}),
    encoding="utf-8",
)
""".replace("/PLACEHOLDER", str(lease_file)),
        encoding="utf-8",
    )
    hook.chmod(0o700)

    commands: list[list[str]] = []
    if command_exists("busybox"):
        commands.append([
            "busybox", "udhcpc", "-i", iface, "-n", "-q",
            "-t", "4", "-T", "3", "-s", str(hook),
        ])
    elif command_exists("udhcpc"):
        commands.append([
            "udhcpc", "-i", iface, "-n", "-q",
            "-t", "4", "-T", "3", "-s", str(hook),
        ])
    if command_exists("dhclient"):
        commands.append(["dhclient", "-1", "-v", "-sf", str(hook), iface])

    debug_lines: list[str] = []
    try:
        for cmd in commands:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                debug_lines.append(
                    f"cmd={' '.join(cmd[:3])} rc={res.returncode} "
                    f"stdout={(res.stdout or '').strip()[-500:]} "
                    f"stderr={(res.stderr or '').strip()[-500:]}"
                )
            except Exception as exc:
                debug_lines.append(f"cmd={' '.join(cmd[:3])} exception={exc}")
                continue
            if lease_file.exists() and interface_has_ipv4(iface):
                try:
                    import json
                    lease = json.loads(lease_file.read_text(encoding="utf-8"))
                    return True, str(lease.get("gateway") or ""), " | ".join(debug_lines)
                except Exception as exc:
                    return True, "", " | ".join(debug_lines + [f"lease_parse={exc}"])

        try:
            link = subprocess.run(
                ["ip", "-d", "link", "show", "dev", iface],
                capture_output=True, text=True, timeout=3,
            )
            debug_lines.append(f"link={(link.stdout or link.stderr).strip()[-800:]}")
            addr = subprocess.run(
                ["ip", "-4", "addr", "show", "dev", iface],
                capture_output=True, text=True, timeout=3,
            )
            debug_lines.append(f"addr={(addr.stdout or addr.stderr).strip()[-500:]}")
        except Exception as exc:
            debug_lines.append(f"iface_debug={exc}")
        return interface_has_ipv4(iface), "", " | ".join(debug_lines)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

class SoftEtherAdapter:
    protocol = "softether"

    @staticmethod
    def available() -> bool:
        return command_exists("vpnclient") and command_exists("vpncmd")

    @staticmethod
    def _vpncmd(*args: str, timeout: int = 12) -> subprocess.CompletedProcess[str]:
        cmd = ["vpncmd", "localhost", "/CLIENT", "/CMD", *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _client_ready(self) -> bool:
        try:
            result = self._vpncmd("AccountList", timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def _ensure_client_service(self) -> tuple[bool, str]:
        if self._client_ready():
            return True, "reused existing SoftEther VPN Client"

        debug: list[str] = []
        if command_exists("systemctl"):
            try:
                result = subprocess.run(
                    ["systemctl", "start", "softether-vpnclient"],
                    capture_output=True, text=True, timeout=10,
                )
                debug.append(
                    f"systemctl rc={result.returncode} "
                    f"out={(result.stdout or '').strip()[-300:]} "
                    f"err={(result.stderr or '').strip()[-500:]}"
                )
                for _ in range(10):
                    if self._client_ready():
                        return True, " | ".join(debug)
                    time.sleep(0.5)
            except Exception as exc:
                debug.append(f"systemctl exception={exc}")

        try:
            result = subprocess.run(
                ["vpnclient", "start"],
                capture_output=True, text=True, timeout=8,
            )
            debug.append(
                f"vpnclient start rc={result.returncode} "
                f"out={(result.stdout or '').strip()[-300:]} "
                f"err={(result.stderr or '').strip()[-500:]}"
            )
            for _ in range(10):
                if self._client_ready():
                    return True, " | ".join(debug)
                time.sleep(0.5)
        except Exception as exc:
            debug.append(f"vpnclient start exception={exc}")

        return False, " | ".join(debug)

    def _wait_account_connected(self, account: str, timeout: float = 15.0) -> tuple[bool, str]:
        deadline = time.time() + timeout
        last_output = ""
        while time.time() < deadline:
            try:
                status = self._vpncmd("AccountStatusGet", account, timeout=5)
                last_output = (status.stdout or "") + (status.stderr or "")
                normalized = " ".join(last_output.lower().split())
                connected_markers = (
                    "connection completed",
                    "session established",
                    "connection status | connected",
                    "connection status|connected",
                )
                if any(marker in normalized for marker in connected_markers):
                    return True, last_output
            except Exception as exc:
                last_output = str(exc)
            time.sleep(1)
        return False, last_output

    def connect(self, host: str, port: int = 443, account: str = "aimili", nic: str = "aimili", username: str = "vpn", password: str = "vpn") -> TunnelResult:
        if not self.available():
            return TunnelResult(False, self.protocol, message="vpnclient/vpncmd not installed")
        before = list_interfaces()
        routes_before = snapshot_main_routes()
        connected_successfully = False
        try:
            # Ubuntu/Debian package normally gets /run/softether from systemd's
            # RuntimeDirectory=. When we intentionally keep the global service
            # disabled, create the runtime directory before starting vpnclient.
            try:
                Path("/run/softether").mkdir(parents=True, exist_ok=True)
                Path("/run/softether").chmod(0o755)
            except OSError:
                pass
            service_ok, service_debug = self._ensure_client_service()
            if not service_ok:
                return TunnelResult(
                    False,
                    self.protocol,
                    message=f"SoftEther VPN Client service unavailable: {service_debug[-1600:]}",
                )
            # Idempotent cleanup. These commands may fail when entries do not exist.
            self._vpncmd("AccountDisconnect", account, timeout=5)
            self._vpncmd("AccountDelete", account, timeout=5)
            self._vpncmd("NicDelete", nic, timeout=5)
            nic_created = self._vpncmd("NicCreate", nic, timeout=8)
            if nic_created.returncode != 0:
                return TunnelResult(False, self.protocol, message=(nic_created.stdout + nic_created.stderr)[-1200:])
            nic_enabled = self._vpncmd("NicEnable", nic, timeout=8)
            if nic_enabled.returncode != 0:
                self.disconnect(account, nic=nic, delete=True)
                return TunnelResult(False, self.protocol, message=(nic_enabled.stdout + nic_enabled.stderr)[-1200:])

            created = self._vpncmd(
                "AccountCreate", account,
                f"/SERVER:{host}:{int(port)}",
                "/HUB:VPNGATE",
                f"/USERNAME:{username}",
                f"/NICNAME:{nic}",
                timeout=10,
            )
            if created.returncode != 0:
                return TunnelResult(False, self.protocol, message=(created.stdout + created.stderr)[-1200:])
            auth = self._vpncmd("AccountPasswordSet", account, f"/PASSWORD:{password}", "/TYPE:standard", timeout=8)
            if auth.returncode != 0:
                self.disconnect(account)
                return TunnelResult(False, self.protocol, message=(auth.stdout + auth.stderr)[-1200:])
            connected = self._vpncmd("AccountConnect", account, timeout=10)
            if connected.returncode != 0:
                return TunnelResult(False, self.protocol, message=(connected.stdout + connected.stderr)[-1200:])

            session_ok, session_status = self._wait_account_connected(account, timeout=15)
            if not session_ok:
                self.disconnect(account, nic=nic, delete=True)
                return TunnelResult(
                    False,
                    self.protocol,
                    message=f"SoftEther session did not reach connected state: {session_status[-1800:]}",
                )

            iface = wait_for_new_interface(before, ("vpn_",), timeout=12)
            if not iface:
                iface = f"vpn_{nic}"
            try:
                subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True, timeout=3)
                subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=3)
            except Exception:
                pass
            dhcp_ok, gateway, dhcp_debug = obtain_dhcp_lease(iface)
            if not dhcp_ok:
                self.disconnect(account)
                return TunnelResult(
                    False,
                    self.protocol,
                    interface=iface,
                    message=f"SoftEther connected but DHCP/IP assignment failed: {dhcp_debug[-1800:]}",
                )
            if not gateway:
                self.disconnect(account)
                return TunnelResult(
                    False,
                    self.protocol,
                    interface=iface,
                    message=f"SoftEther DHCP lease did not provide a gateway: {dhcp_debug[-1200:]}",
                )
            added_routes = added_cleanup_host_routes(routes_before)
            connected_successfully = True
            return TunnelResult(
                True,
                self.protocol,
                interface=iface,
                gateway=gateway,
                message="SoftEther connected",
                details={
                    "account": account,
                    "nic": nic,
                    "added_host_routes": added_routes,
                },
            )
        except Exception as exc:
            return TunnelResult(False, self.protocol, message=str(exc))
        finally:
            if not connected_successfully:
                try:
                    self.disconnect(account, nic=nic, delete=True)
                except Exception:
                    pass
                cleanup_route_lines(added_cleanup_host_routes(routes_before))

    def disconnect(
        self,
        account: str = "aimili",
        nic: str | None = None,
        delete: bool = False,
        added_routes: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> None:
        if not self.available():
            cleanup_route_lines(added_routes)
            return
        try:
            self._vpncmd("AccountDisconnect", account, timeout=6)
        except Exception:
            pass
        if delete:
            try:
                self._vpncmd("AccountDelete", account, timeout=6)
            except Exception:
                pass
            if nic:
                try:
                    self._vpncmd("NicDelete", nic, timeout=6)
                except Exception:
                    pass
        cleanup_route_lines(added_routes)

class SSTPAdapter:
    protocol = "sstp"

    @staticmethod
    def available() -> bool:
        return command_exists("sstpc") and command_exists("pppd")

    def connect(self, hostname: str, username: str = "vpn", password: str = "vpn", timeout: int = 20) -> TunnelResult:
        if not self.available():
            return TunnelResult(False, self.protocol, message="sstpc/pppd not installed")
        before = list_interfaces()
        routes_before = snapshot_main_routes()
        connected_successfully = False
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
            ip_deadline = time.time() + max(4.0, min(float(timeout), 15.0))
            while time.time() < ip_deadline:
                if interface_has_ipv4(iface):
                    connected_successfully = True
                    return TunnelResult(
                        True,
                        self.protocol,
                        interface=iface,
                        message="SSTP connected",
                        process=proc,
                        details={"added_host_routes": added_cleanup_host_routes(routes_before)},
                    )
                if proc.poll() is not None:
                    output = ""
                    try:
                        output = (proc.stdout.read() if proc.stdout else "")[-1800:]
                    except Exception:
                        pass
                    return TunnelResult(
                        False,
                        self.protocol,
                        interface=iface,
                        message=output or "SSTP/PPP exited before IPv4 assignment",
                        process=proc,
                    )
                time.sleep(0.5)

            output = ""
            try:
                if proc.stdout:
                    import select
                    ready, _, _ = select.select([proc.stdout], [], [], 0)
                    if ready:
                        output = proc.stdout.read(1800) or ""
            except Exception:
                pass
            proc.terminate()
            return TunnelResult(
                False,
                self.protocol,
                interface=iface,
                message=f"SSTP PPP interface has no IPv4 address after wait. {output[-1500:]}",
                process=proc,
            )
        except Exception as exc:
            return TunnelResult(False, self.protocol, message=str(exc))
        finally:
            if not connected_successfully:
                cleanup_route_lines(added_cleanup_host_routes(routes_before))

    @staticmethod
    def disconnect(
        process: subprocess.Popen[str] | None,
        added_routes: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> None:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
        cleanup_route_lines(added_routes)

class L2TPIPsecAdapter:
    protocol = "l2tp-ipsec"

    def __init__(self) -> None:
        self._active: dict[str, TunnelResult] = {}

    @staticmethod
    def available() -> bool:
        required = ("ip", "iptables", "unshare", "ipsec", "xl2tpd", "pppd")
        return all(command_exists(cmd) for cmd in required)

    @staticmethod
    def _validate_host(host: str) -> str:
        host = str(host or "").strip()
        if not host:
            raise ValueError("empty L2TP server host")
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("invalid L2TP server hostname")
        return host

    @staticmethod
    def _physical_interface() -> str:
        try:
            res = subprocess.run(
                ["ip", "-o", "route", "show", "default"],
                capture_output=True, text=True, timeout=3,
            )
            for line in res.stdout.splitlines():
                parts = line.split()
                if "dev" in parts:
                    iface = parts[parts.index("dev") + 1]
                    if iface and not iface.startswith(("tun", "tap", "ppp", "vpn_", "veth")):
                        return iface
        except Exception:
            pass
        return ""

    @staticmethod
    def _run(cmd: list[str], timeout: int = 8, check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)

    @staticmethod
    def _ns_exec(namespace: str, cmd: list[str], timeout: int = 8, check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["ip", "netns", "exec", namespace, *cmd],
            capture_output=True, text=True, timeout=timeout, check=check,
        )

    @staticmethod
    def _cleanup_iptables(subnet: str, physical: str) -> None:
        if not subnet or not physical:
            return
        rules = [
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", physical, "-j", "MASQUERADE"],
            ["iptables", "-D", "FORWARD", "-s", subnet, "-o", physical, "-j", "ACCEPT"],
            ["iptables", "-D", "FORWARD", "-d", subnet, "-i", physical, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
        for rule in rules:
            try:
                subprocess.run(rule, capture_output=True, timeout=3)
            except Exception:
                pass

    @staticmethod
    def _token(namespace: str) -> tuple[str, int]:
        digest = hashlib.sha256(namespace.encode("utf-8")).digest()
        slot = 16 + (digest[0] % 180)
        token = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:6]
        return token, slot

    def connect(
        self,
        host: str,
        username: str = "vpn",
        password: str = "vpn",
        psk: str = "vpn",
        namespace: str = "aimili-l2tp",
        timeout: int = 35,
    ) -> TunnelResult:
        if not self.available():
            return TunnelResult(False, self.protocol, message="L2TP/IPsec dependencies are not installed")
        try:
            host = self._validate_host(host)
        except Exception as exc:
            return TunnelResult(False, self.protocol, message=str(exc))

        # Resolve before entering the network namespace. Ubuntu often uses a
        # loopback DNS stub (127.0.0.53) that is not reachable inside a fresh
        # netns. VPNGate L2TP/IPsec accepts the server IPv4 address directly.
        resolved_host = host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, 1701, socket.AF_INET, socket.SOCK_DGRAM)
                if not infos:
                    raise OSError("no IPv4 address returned")
                resolved_host = str(infos[0][4][0])
            except Exception as exc:
                return TunnelResult(False, self.protocol, message=f"Unable to resolve L2TP server {host}: {exc}")

        namespace = re.sub(r"[^A-Za-z0-9_.-]+", "-", namespace)[:31] or "aimili-l2tp"
        self.disconnect(namespace)

        token, slot = self._token(namespace)
        host_veth = f"alh{token}"[:15]
        ns_veth = f"aln{token}"[:15]
        subnet = f"10.254.{slot}.0/30"
        host_ip = f"10.254.{slot}.1"
        ns_ip = f"10.254.{slot}.2"
        physical = self._physical_interface()
        if not physical:
            return TunnelResult(False, self.protocol, message="Unable to determine physical egress interface")

        work_dir = Path(tempfile.mkdtemp(prefix=f"aimili-{namespace}-"))
        run_dir = work_dir / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        ipsec_conf = work_dir / "ipsec.conf"
        ipsec_secrets = work_dir / "ipsec.secrets"
        xl2tp_conf = work_dir / "xl2tpd.conf"
        l2tp_secrets = work_dir / "l2tp-secrets"
        ppp_options = work_dir / "ppp-options"
        control_file = work_dir / "l2tp-control"
        pid_file = work_dir / "xl2tpd.pid"
        ipsec_log = work_dir / "ipsec.log"
        xl2tp_log = work_dir / "xl2tpd.log"
        ppp_log = work_dir / "ppp.log"
        helper = work_dir / "run-l2tp.sh"

        def collect_l2tp_logs(prefix: str = "") -> str:
            parts: list[str] = [prefix] if prefix else []
            for label, log_path in (
                ("ipsec", ipsec_log),
                ("xl2tpd", xl2tp_log),
                ("ppp", ppp_log),
            ):
                try:
                    if log_path.exists():
                        text = log_path.read_text(encoding="utf-8", errors="replace")
                        parts.append(f"--- {label} ---\n{text[-5000:]}")
                except Exception as exc:
                    parts.append(f"--- {label} read error: {exc} ---")
            return "\n".join(part for part in parts if part)[-12000:]

        ipsec_conf.write_text(
            f"""config setup
    uniqueids=no

conn vpngate
    keyexchange=ikev1
    authby=psk
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right={resolved_host}
    rightprotoport=17/1701
    rightid=%any
    forceencaps=yes
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha1,aes128-sha1,3des-sha1!
    keyingtries=1
    dpdaction=clear
    dpddelay=20s
    rekey=no
    auto=add
""",
            encoding="utf-8",
        )
        ipsec_secrets.write_text(f': PSK "{psk}"\n', encoding="utf-8")
        try:
            ipsec_secrets.chmod(0o600)
        except OSError:
            pass

        ppp_options.write_text(
            f"""name {username}
password {password}
noauth
refuse-eap
noccp
noipdefault
nodefaultroute
ipcp-accept-local
ipcp-accept-remote
usepeerdns
mtu 1360
mru 1360
nopersist
maxfail 1
debug
logfile {ppp_log}
""",
            encoding="utf-8",
        )
        try:
            ppp_options.chmod(0o600)
        except OSError:
            pass

        xl2tp_conf.write_text(
            f"""[global]
port = 1701

[lac vpngate]
lns = {resolved_host}
pppoptfile = {ppp_options}
redial = no
autodial = no
length bit = yes
""",
            encoding="utf-8",
        )
        l2tp_secrets.write_text("", encoding="utf-8")

        helper.write_text(
            f"""#!/usr/bin/env bash
set -euo pipefail
mount --make-rprivate /
mount --bind "{run_dir}" /run
mount --bind "{ipsec_secrets}" /etc/ipsec.secrets

cleanup() {{
  set +e
  if [ -S "{control_file}" ] || [ -e "{control_file}" ]; then
    echo "d vpngate" > "{control_file}"
  fi
  timeout 3s ipsec down vpngate >/dev/null 2>&1 || true
  if [ -n "${{XL2TP_PID:-}}" ]; then
    kill "$XL2TP_PID" >/dev/null 2>&1 || true
    wait "$XL2TP_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "${{STARTER_PID:-}}" ]; then
    kill "$STARTER_PID" >/dev/null 2>&1 || true
    wait "$STARTER_PID" >/dev/null 2>&1 || true
  fi
}}
trap cleanup EXIT INT TERM

ipsec start --nofork --conf "{ipsec_conf}" >"{ipsec_log}" 2>&1 &
STARTER_PID=$!
sleep 2
timeout 15s ipsec up vpngate >>"{ipsec_log}" 2>&1
xl2tpd -D -c "{xl2tp_conf}" -s "{l2tp_secrets}" -p "{pid_file}" -C "{control_file}" >"{xl2tp_log}" 2>&1 &
XL2TP_PID=$!
for _ in $(seq 1 20); do
  [ -e "{control_file}" ] && break
  sleep 0.25
done
echo "c vpngate" > "{control_file}"
for _ in $(seq 1 60); do
  IFACE=$(ip -o link show | awk -F': ' '$2 ~ /^ppp[0-9]+$/ {{print $2; exit}}')
  if [ -n "$IFACE" ] && ip -4 -o addr show dev "$IFACE" | grep -q ' inet '; then
    ip route replace default dev "$IFACE"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
    echo "$IFACE" > "{work_dir / 'ppp-iface'}"
    touch "{work_dir / 'ready'}"
    wait "$XL2TP_PID"
    exit $?
  fi
  sleep 0.5
done
echo "PPP interface did not become ready" >&2
exit 42
""",
            encoding="utf-8",
        )
        helper.chmod(0o700)

        try:
            self._run(["ip", "netns", "add", namespace], timeout=5, check=True)
            self._run(["ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_veth], timeout=5, check=True)
            self._run(["ip", "link", "set", ns_veth, "netns", namespace], timeout=5, check=True)
            self._run(["ip", "addr", "add", f"{host_ip}/30", "dev", host_veth], timeout=5, check=True)
            self._run(["ip", "link", "set", host_veth, "up"], timeout=5, check=True)

            self._ns_exec(namespace, ["ip", "link", "set", "lo", "up"], timeout=5, check=True)
            self._ns_exec(namespace, ["ip", "addr", "add", f"{ns_ip}/30", "dev", ns_veth], timeout=5, check=True)
            self._ns_exec(namespace, ["ip", "link", "set", ns_veth, "up"], timeout=5, check=True)
            self._ns_exec(namespace, ["ip", "route", "replace", "default", "via", host_ip, "dev", ns_veth], timeout=5, check=True)

            try:
                self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=3)
            except Exception:
                pass

            nat_rules = [
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", physical, "-j", "MASQUERADE"],
                ["iptables", "-A", "FORWARD", "-s", subnet, "-o", physical, "-j", "ACCEPT"],
                ["iptables", "-A", "FORWARD", "-d", subnet, "-i", physical, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ]
            for rule in nat_rules:
                # disconnect() removes the deterministic rules first, so add once.
                self._run(rule, timeout=4, check=True)

            proc = subprocess.Popen(
                ["ip", "netns", "exec", namespace, "unshare", "--mount", "--propagation", "private", str(helper)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            deadline = time.time() + timeout
            ready = work_dir / "ready"
            iface_file = work_dir / "ppp-iface"
            while time.time() < deadline:
                if proc.poll() is not None:
                    output = ""
                    try:
                        output = (proc.stdout.read() if proc.stdout else "")[-2000:]
                    except Exception:
                        pass
                    diagnostic = collect_l2tp_logs(output or "L2TP helper exited before PPP became ready")
                    self.disconnect(namespace)
                    shutil.rmtree(work_dir, ignore_errors=True)
                    return TunnelResult(False, self.protocol, message=diagnostic)
                if ready.exists() and iface_file.exists():
                    inner_iface = iface_file.read_text(encoding="utf-8").strip()
                    result = TunnelResult(
                        True,
                        self.protocol,
                        interface=host_veth,
                        gateway=ns_ip,
                        namespace=namespace,
                        inner_interface=inner_iface,
                        work_dir=str(work_dir),
                        message="L2TP/IPsec connected in isolated network namespace",
                        process=proc,
                        details={"subnet": subnet, "physical": physical},
                    )
                    self._active[namespace] = result
                    return result
                time.sleep(0.5)

            timeout_output = ""
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            pass
            except Exception:
                pass

            # Kill namespace descendants BEFORE reading the helper pipe.
            # charon/stroke inherit stdout and otherwise keep the pipe open forever.
            self.disconnect(namespace)

            try:
                if proc.stdout:
                    import select
                    chunks: list[str] = []
                    deadline_logs = time.time() + 2.0
                    while time.time() < deadline_logs:
                        ready_fds, _, _ = select.select([proc.stdout], [], [], 0.2)
                        if not ready_fds:
                            if proc.poll() is not None:
                                break
                            continue
                        chunk = proc.stdout.read(3000)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if sum(len(x) for x in chunks) >= 6000:
                            break
                    timeout_output = "".join(chunks)[-4000:]
            except Exception as exc:
                timeout_output = f"log_capture_error={exc}"

            combined_logs = collect_l2tp_logs(timeout_output)
            shutil.rmtree(work_dir, ignore_errors=True)
            return TunnelResult(
                False,
                self.protocol,
                message=f"L2TP/IPsec connection timed out after {timeout}s. {combined_logs}",
            )
        except Exception as exc:
            self._cleanup_iptables(subnet, physical)
            try:
                subprocess.run(["ip", "netns", "del", namespace], capture_output=True, timeout=5)
            except Exception:
                pass
            try:
                subprocess.run(["ip", "link", "del", host_veth], capture_output=True, timeout=5)
            except Exception:
                pass
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass
            return TunnelResult(False, self.protocol, message=str(exc))

    def disconnect(self, namespace: str = "aimili-l2tp") -> None:
        namespace = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(namespace or "aimili-l2tp"))[:31]
        result = self._active.pop(namespace, None)
        token, slot = self._token(namespace)
        physical = self._physical_interface()
        subnet = f"10.254.{slot}.0/30"

        if result and result.process and result.process.poll() is None:
            result.process.terminate()
            try:
                result.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                result.process.kill()

        try:
            pids = self._run(["ip", "netns", "pids", namespace], timeout=3).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), 15)
                except Exception:
                    pass
            if pids:
                time.sleep(0.5)
            remaining = self._run(["ip", "netns", "pids", namespace], timeout=3).stdout.split()
            for pid in remaining:
                try:
                    os.kill(int(pid), 9)
                except Exception:
                    pass
            if remaining:
                time.sleep(0.2)
        except Exception:
            pass

        try:
            subprocess.run(["ip", "netns", "del", namespace], capture_output=True, timeout=6)
        except Exception:
            pass
        try:
            subprocess.run(["ip", "link", "del", f"alh{token}"[:15]], capture_output=True, timeout=5)
        except Exception:
            pass
        self._cleanup_iptables(subnet, physical)

        if result and result.work_dir:
            try:
                shutil.rmtree(result.work_dir, ignore_errors=True)
            except Exception:
                pass

    @staticmethod
    def environment_report(run_kernel_test: bool = False) -> dict[str, Any]:
        required = ("ip", "iptables", "unshare", "ipsec", "xl2tpd", "pppd", "curl", "mount")
        missing = [cmd for cmd in required if not command_exists(cmd)]
        report: dict[str, Any] = {
            "root": os.geteuid() == 0,
            "missing_commands": missing,
            "netns_supported": Path("/proc/self/ns/net").exists(),
            "mount_namespace_supported": Path("/proc/self/ns/mnt").exists(),
            "kernel_test_ran": False,
            "kernel_test_ok": None,
            "kernel_test_error": "",
        }
        if run_kernel_test and report["root"] and not missing:
            report["kernel_test_ran"] = True
            test_ns = f"aimili-check-{os.getpid()}"
            try:
                subprocess.run(["ip", "netns", "del", test_ns], capture_output=True, timeout=3)
                subprocess.run(["ip", "netns", "add", test_ns], capture_output=True, text=True, timeout=5, check=True)
                subprocess.run(
                    ["ip", "netns", "exec", test_ns, "unshare", "--mount", "--propagation", "private", "true"],
                    capture_output=True, text=True, timeout=5, check=True,
                )
                report["kernel_test_ok"] = True
            except Exception as exc:
                report["kernel_test_ok"] = False
                report["kernel_test_error"] = str(exc)
            finally:
                try:
                    subprocess.run(["ip", "netns", "del", test_ns], capture_output=True, timeout=5)
                except Exception:
                    pass
        report["ready"] = bool(
            report["root"]
            and not missing
            and report["netns_supported"]
            and report["mount_namespace_supported"]
            and (report["kernel_test_ok"] is not False)
        )
        return report

    @staticmethod
    def egress_check(result: TunnelResult, timeout: int = 7) -> dict[str, Any]:
        if not result.namespace or not result.inner_interface:
            return {"ok": False, "error": "L2TP namespace/interface missing"}
        cmd = [
            "ip", "netns", "exec", result.namespace,
            "curl", "-s",
            "--interface", f"if!{result.inner_interface}",
            "-w", "\\n%{time_total} %{http_code}",
            "http://api.ipify.org",
            "--max-time", "6",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode != 0:
                return {"ok": False, "error": (res.stderr or f"curl exit {res.returncode}")[-500:]}
            lines = res.stdout.strip().splitlines()
            if len(lines) < 2:
                return {"ok": False, "error": "L2TP egress check returned no data"}
            timing = lines[-1].split()
            if len(timing) != 2 or timing[1] != "200":
                return {"ok": False, "error": f"L2TP egress HTTP error: {lines[-1]}"}
            return {
                "ok": True,
                "ip": lines[0].strip(),
                "latency_ms": int(float(timing[0]) * 1000),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

def capability_report() -> dict[str, Any]:
    return {
        "openvpn": {"installed": command_exists("openvpn"), "activation": "enabled"},
        "softether": {"installed": SoftEtherAdapter.available(), "activation": "development"},
        "sstp": {"installed": SSTPAdapter.available(), "activation": "development"},
        "l2tp_ipsec": {
            "installed": L2TPIPsecAdapter.available(),
            "activation": "development-netns",
            "environment": L2TPIPsecAdapter.environment_report(run_kernel_test=False),
        },
    }

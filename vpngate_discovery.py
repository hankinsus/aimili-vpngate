#!/usr/bin/env python3
from __future__ import annotations

import html
import re
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

VPNGATE_HTML_URL = "https://www.vpngate.net/en/"

class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, Any]]] = []
        self._row: list[dict[str, Any]] | None = None
        self._cell: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = dict(attrs)
        if tag == "tr":
            self._row = []
        elif tag == "td" and self._row is not None:
            self._cell = {"text": [], "links": [], "html": []}
        elif self._cell is not None:
            if tag == "a" and attrs_d.get("href"):
                self._cell["links"].append(attrs_d["href"])
            self._cell["html"].append(self.get_starttag_text() or "")

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._row is not None and self._cell is not None:
            self._cell["text"] = " ".join(" ".join(self._cell["text"]).split())
            self._row.append(self._cell)
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if len(self._row) >= 10:
                self.rows.append(self._row)
            self._row = None
            self._cell = None

def _int(text: str) -> int:
    m = re.search(r"([\d,]+)", text or "")
    return int(m.group(1).replace(",", "")) if m else 0

def _speed_bps(text: str) -> int:
    m = re.search(r"([\d,.]+)\s*Mbps", text or "", re.I)
    if not m:
        return 0
    try:
        return int(float(m.group(1).replace(",", "")) * 1_000_000)
    except ValueError:
        return 0

def _ping_ms(text: str) -> int:
    m = re.search(r"Ping:\s*([\d,.]+)\s*ms", text or "", re.I)
    if not m:
        return 0
    try:
        return int(float(m.group(1).replace(",", "")))
    except ValueError:
        return 0

def _hostname_and_ip(cell_text: str) -> tuple[str, str]:
    hostname = ""
    ip = ""
    hm = re.search(r"([a-z0-9][a-z0-9.-]*\.opengw\.net)", cell_text or "", re.I)
    if hm:
        hostname = hm.group(1).lower()
    im = re.search(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])", cell_text or "")
    if im:
        ip = im.group(1)
    return hostname, ip

def _openvpn_ports(links: list[str]) -> tuple[str, str, int, int]:
    hostname = ""
    ip = ""
    tcp = 0
    udp = 0
    for href in links:
        if not href.startswith("do_openvpn.aspx?"):
            continue
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
        hostname = (qs.get("fqdn") or [""])[0].lower()
        ip = (qs.get("ip") or [""])[0]
        try:
            tcp = int((qs.get("tcp") or ["0"])[0] or 0)
        except ValueError:
            tcp = 0
        try:
            udp = int((qs.get("udp") or ["0"])[0] or 0)
        except ValueError:
            udp = 0
        break
    return hostname, ip, tcp, udp

def parse_server_table(raw_html: str) -> list[dict[str, Any]]:
    parser = _TableParser()
    parser.feed(raw_html)

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for cells in parser.rows:
        if len(cells) < 10:
            continue
        country = str(cells[0].get("text") or "").strip()
        host_cell = str(cells[1].get("text") or "")
        hostname, ip = _hostname_and_ip(host_cell)

        ovpn_host, ovpn_ip, ovpn_tcp, ovpn_udp = _openvpn_ports(cells[6].get("links") or [])
        hostname = ovpn_host or hostname
        ip = ovpn_ip or ip

        if not hostname and not ip:
            continue
        if "country" in country.lower() and not ip:
            continue

        identity = (hostname, ip)
        if identity in seen:
            continue
        seen.add(identity)

        protocols: list[dict[str, Any]] = []

        # SoftEther column (td[4]): e.g. "TCP: 443 UDP: Supported"
        softether_text = str(cells[4].get("text") or "")
        sm = re.search(r"TCP:\s*(\d+)", softether_text, re.I)
        if sm:
            se_port = int(sm.group(1))
            protocols.append({"protocol": "softether", "transport": "tcp", "port": se_port})
            if re.search(r"UDP:\s*Supported", softether_text, re.I):
                protocols.append({"protocol": "softether", "transport": "udp", "port": se_port})

        # L2TP has fixed protocol ports; keep port=0 because it is a compound
        # IPsec/L2TP endpoint rather than one TCP/UDP service port.
        l2tp_links = cells[5].get("links") or []
        if any("howto_l2tp.aspx" in href for href in l2tp_links):
            protocols.append({"protocol": "l2tp-ipsec", "transport": "udp", "port": 0})

        if ovpn_tcp:
            protocols.append({"protocol": "openvpn", "transport": "tcp", "port": ovpn_tcp})
        if ovpn_udp:
            protocols.append({"protocol": "openvpn", "transport": "udp", "port": ovpn_udp})

        # SSTP hostname can differ from the displayed DDNS hostname and may
        # include a non-443 port in the protocol cell.
        sstp_text = str(cells[7].get("text") or "")
        sstp_links = cells[7].get("links") or []
        if any("howto_sstp.aspx" in href for href in sstp_links):
            sstp_host = hostname
            sstp_port = 443
            sm = re.search(r"SSTP\s*Hostname\s*:\s*([a-z0-9.-]+\.opengw\.net)(?::(\d+))?", sstp_text, re.I)
            if sm:
                sstp_host = sm.group(1).lower()
                if sm.group(2):
                    sstp_port = int(sm.group(2))
            protocols.append({
                "protocol": "sstp",
                "transport": "tcp",
                "port": sstp_port,
                "hostname": sstp_host,
            })

        if not protocols:
            continue

        results.append({
            "hostname": hostname,
            "ip": ip,
            "country": country,
            "sessions": _int(str(cells[2].get("text") or "")),
            "speed": _speed_bps(str(cells[3].get("text") or "")),
            "ping": _ping_ms(str(cells[3].get("text") or "")),
            "score": _int(str(cells[9].get("text") or "")),
            "protocols": protocols,
        })

    return results

def fetch_server_table(url: str = VPNGATE_HTML_URL, timeout: int = 15) -> list[dict[str, Any]]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 AimiliVPN/3.0",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    return parse_server_table(raw)

#!/usr/bin/env python3
"""
pcap_analyzer.py - Offline PCAP threat-hunting tool for SOC workflows.

Detections:
  * Traffic summary ....... protocol breakdown, top talkers, top conversations
  * Port scan ............. SYN fan-out (vertical / horizontal / block scans)
  * C2 beaconing .......... low-jitter periodic callbacks via inter-arrival analysis
  * DNS tunneling ......... Shannon entropy + label-length profiling of subdomains
  * Cleartext creds ....... HTTP POST / Basic auth, FTP, Telnet, SMTP, POP3, IMAP

Usage:
    python pcap_analyzer.py -r capture.pcap --all
    python pcap_analyzer.py -r capture.pcap --scan --beacon
    python pcap_analyzer.py -r capture.pcap --all --json report.json

Author: Sujal Chetan Parmar
License: MIT
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import math
import os
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from scapy.all import PcapReader, conf  # noqa: F401
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw
except ImportError:  # pragma: no cover
    sys.exit("[!] scapy is not installed.  Run:  pip install -r requirements.txt")


# ──────────────────────────────────────────────────────────────────────────────
#  Terminal helpers
# ──────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI colours, auto-disabled when not writing to a TTY or NO_COLOR is set."""
    _on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    DIM = "\033[2m" if _on else ""
    RED = "\033[31m" if _on else ""
    GREEN = "\033[32m" if _on else ""
    YELLOW = "\033[33m" if _on else ""
    BLUE = "\033[34m" if _on else ""
    CYAN = "\033[36m" if _on else ""

    @classmethod
    def disable(cls) -> None:
        for attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "BLUE", "CYAN"):
            setattr(cls, attr, "")


def severity_colour(sev: str) -> str:
    return {"CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
            "MEDIUM": C.YELLOW, "LOW": C.CYAN}.get(sev, "")


def render_table(headers: List[str],
                 rows: List[List[Any]],
                 aligns: Optional[List[str]] = None,
                 max_width: int = 46) -> str:
    """Render a unicode box table with no third-party dependency."""
    if not rows:
        return f"{C.DIM}  (no results){C.RESET}"

    str_rows = [[("" if c is None else str(c)) for c in r] for r in rows]
    for r in str_rows:
        for i, cell in enumerate(r):
            if len(cell) > max_width:
                r[i] = cell[: max_width - 1] + "\u2026"

    ncols = len(headers)
    aligns = aligns or ["l"] * ncols
    widths = [len(h) for h in headers]
    for r in str_rows:
        for i in range(ncols):
            widths[i] = max(widths[i], len(re.sub(r"\x1b\[[0-9;]*m", "", r[i])) if i < len(r) else 0)

    def line(l: str, m: str, r: str) -> str:
        return l + m.join("\u2500" * (w + 2) for w in widths) + r

    def fmt(cells: List[str], bold: bool = False) -> str:
        out = []
        for i in range(ncols):
            cell = cells[i] if i < len(cells) else ""
            gap = " " * (widths[i] - len(re.sub(r"\x1b\[[0-9;]*m", "", cell))); pad = gap + cell if aligns[i] == "r" else cell + gap
            out.append(f" {C.BOLD if bold else ''}{pad}{C.RESET if bold else ''} ")
        return "\u2502" + "\u2502".join(out) + "\u2502"

    parts = [line("\u250c", "\u252c", "\u2510"),
             fmt(headers, bold=True),
             line("\u251c", "\u253c", "\u2524")]
    parts += [fmt(r) for r in str_rows]
    parts.append(line("\u2514", "\u2534", "\u2518"))
    return "\n".join("  " + p for p in parts)


def banner(text: str) -> str:
    bar = "\u2550" * 76
    return f"\n{C.BLUE}{bar}\n  {C.BOLD}{text}{C.RESET}{C.BLUE}\n{bar}{C.RESET}"


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_duration(sec: float) -> str:
    if sec < 1:
        return f"{sec * 1000:.0f}ms"
    if sec < 60:
        return f"{sec:.1f}s"
    if sec < 3600:
        return f"{int(sec // 60)}m {int(sec % 60)}s"
    return f"{int(sec // 3600)}h {int((sec % 3600) // 60)}m"


def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ──────────────────────────────────────────────────────────────────────────────
#  Findings
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# David Bianco's Pyramid of Pain: how costly each indicator type is for an
# attacker to change once you act on it. Bottom = trivial for them to
# rotate (blocking one IP costs nothing to work around); top = expensive
# (changing a whole TTP means rebuilding their tooling/workflow).
# (level name, tier out of 6, one-line reason this module sits at that tier)
PYRAMID_OF_PAIN = {
    "port_scan": ("IP Addresses", 2,
                 "Blocking the source IP stops this instance, but costs an "
                 "attacker nothing to rotate to a new one."),
    "dns_tunneling": ("Domain Names", 3,
                      "Blocking the domain works until the attacker "
                      "registers a new one - cheap, but not free, for them."),
    "credentials": ("Host Artifacts", 4,
                    "Tied to how the credential was transmitted on that "
                    "host/protocol; fixing it forces a real config change."),
    "vuln_scan": ("Host Artifacts", 4,
                 "Tied to the specific vulnerable software version on that "
                 "host; patching removes it but is still one host at a time."),
    "beaconing": ("TTPs", 6,
                 "This is the attacker's actual operational behaviour - "
                 "changing it means rebuilding their tooling, the most "
                 "costly thing you can make an attacker do."),
}


def pyramid_info(module: str) -> Tuple[str, int, str]:
    return PYRAMID_OF_PAIN.get(module, ("Unclassified", 0, ""))


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    src: str = ""
    dst: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre: str = ""
    pyramid: str = ""       # e.g. "TTPs (tier 6/6)"
    pyramid_tier: int = 0   # 1 (trivial) - 6 (tough), 0 = unclassified

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def annotate_pyramid(findings: List[Finding]) -> None:
    """Stamp every finding with its Pyramid of Pain tier, in place."""
    for f in findings:
        name, tier, reason = pyramid_info(f.module)
        f.pyramid = f"{name} (tier {tier}/6)" if tier else name
        f.pyramid_tier = tier
        f.evidence.setdefault("pyramid_reason", reason)


# ──────────────────────────────────────────────────────────────────────────────
#  Packet ingestion
# ──────────────────────────────────────────────────────────────────────────────

WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5985: "winrm", 5986: "winrm-s", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
}

HTTP_PORTS = {80, 591, 3128, 8000, 8008, 8080, 8081, 8088, 8888}


@dataclass
class PacketRecord:
    """Flattened, cheap-to-store view of one packet."""
    __slots__ = ("ts", "size", "proto", "src", "dst", "sport", "dport",
                 "flags", "payload")
    ts: float
    size: int
    proto: str
    src: str
    dst: str
    sport: int
    dport: int
    flags: str
    payload: bytes


class Capture:
    """Streams a PCAP once and holds the flattened records + metadata."""

    def __init__(self, path: str, bpf_src: str = "", max_packets: int = 0,
                 keep_payload_bytes: int = 1400):
        self.path = path
        self.packets: List[PacketRecord] = []
        self.dns_queries: List[Tuple[float, str, str, str, str]] = []  # ts, src, qname, qtype, dst
        self.dns_answers: List[Tuple[float, str, str]] = []            # ts, qname, rdata
        self.proto_counter: Counter = Counter()
        self.l2_counter: Counter = Counter()
        self.total_packets = 0
        self.malformed = 0
        self.non_ip = 0
        self.bytes_total = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.keep_payload_bytes = keep_payload_bytes
        self._filter_src = bpf_src
        self._max = max_packets
        self.read_seconds = 0.0

    # -- ingestion ---------------------------------------------------------
    def load(self, verbose: bool = True) -> "Capture":
        if not os.path.isfile(self.path):
            sys.exit(f"[!] File not found: {self.path}")
        start = time.time()
        if verbose:
            size = os.path.getsize(self.path)
            print(f"{C.DIM}[*] Reading {self.path} ({human_bytes(size)}) ...{C.RESET}")

        try:
            reader = PcapReader(self.path)
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"[!] Could not open capture: {exc}")

        with reader:
            for pkt in reader:
                self.total_packets += 1
                if self._max and self.total_packets > self._max:
                    self.total_packets -= 1
                    break
                try:
                    self._ingest(pkt)
                except Exception:  # noqa: BLE001 - never die on one bad packet
                    self.malformed += 1

        self.read_seconds = time.time() - start
        if verbose:
            print(f"{C.DIM}[*] Parsed {self.total_packets:,} packets "
                  f"in {self.read_seconds:.2f}s "
                  f"({self.malformed} malformed, {self.non_ip} non-IP){C.RESET}")
        return self

    def _ingest(self, pkt) -> None:
        ts = float(pkt.time)
        # wirelen comes straight from the pcap record header - using len(pkt)
        # would force scapy to re-serialise the packet on every call.
        size = getattr(pkt, "wirelen", None) or len(pkt)
        self.bytes_total += size
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts

        # One traversal of the layer stack instead of a chain of haslayer()
        # calls, each of which walks the packet again.
        layers = pkt.layers()

        if Ether in layers:
            self.l2_counter["Ethernet"] += 1
        if ARP in layers:
            self.l2_counter["ARP"] += 1
            self.proto_counter["ARP"] += 1
            self.non_ip += 1
            return

        if IP in layers:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
        elif IPv6 in layers:
            ip6 = pkt[IPv6]
            src, dst = ip6.src, ip6.dst
            self.proto_counter["IPv6"] += 1
        else:
            self.non_ip += 1
            self.proto_counter["non-IP"] += 1
            return

        if self._filter_src and src != self._filter_src:
            return

        sport = dport = 0
        flags = ""
        proto = "IP"
        payload = b""

        has_raw = Raw in layers
        if TCP in layers:
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            flags = str(tcp.flags)
            proto = "TCP"
            self.proto_counter["TCP"] += 1
            if has_raw:
                payload = bytes(pkt[Raw].load)[: self.keep_payload_bytes]
        elif UDP in layers:
            udp = pkt[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            proto = "UDP"
            self.proto_counter["UDP"] += 1
            if has_raw:
                payload = bytes(pkt[Raw].load)[: self.keep_payload_bytes]
        elif ICMP in layers:
            proto = "ICMP"
            self.proto_counter["ICMP"] += 1
            if has_raw:
                payload = bytes(pkt[Raw].load)[:64]
        else:
            self.proto_counter["other-IP"] += 1

        # DNS is parsed inline so we only walk the capture once.
        if DNS in layers:
            self.proto_counter["DNS"] += 1
            self._ingest_dns(pkt, ts, src, dst)
        elif proto == "TCP" and (dport in HTTP_PORTS or sport in HTTP_PORTS):
            self.proto_counter["HTTP"] += 1
        elif proto == "TCP" and (dport == 443 or sport == 443):
            self.proto_counter["TLS"] += 1

        self.packets.append(
            PacketRecord(ts, size, proto, src, dst, sport, dport, flags, payload)
        )

    def _ingest_dns(self, pkt, ts: float, src: str, dst: str) -> None:
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd:
            qds = dns.qd if isinstance(dns.qd, list) else [dns.qd]
            for qd in qds:
                try:
                    qname = qd.qname.decode("utf-8", "replace").rstrip(".")
                    qtype = DNSQR.qtype.i2s.get(int(qd.qtype), str(qd.qtype))
                except Exception:  # noqa: BLE001
                    continue
                if qname:
                    self.dns_queries.append((ts, src, qname.lower(), qtype, dst))
        elif dns.qr == 1 and dns.an:
            for i in range(int(dns.ancount or 0)):
                try:
                    rr = dns.an[i]
                    name = rr.rrname.decode("utf-8", "replace").rstrip(".").lower()
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", "replace")
                    elif isinstance(rdata, list):
                        rdata = " ".join(
                            x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x)
                            for x in rdata)
                    self.dns_answers.append((ts, name, str(rdata)))
                except Exception:  # noqa: BLE001
                    continue

    # -- convenience -------------------------------------------------------
    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def tcp_syns(self) -> Iterable[PacketRecord]:
        """SYN packets that are not SYN/ACK (i.e. connection initiations)."""
        for p in self.packets:
            if p.proto == "TCP" and "S" in p.flags and "A" not in p.flags:
                yield p


# ──────────────────────────────────────────────────────────────────────────────
#  Module 1 - Traffic summary
# ──────────────────────────────────────────────────────────────────────────────

def module_summary(cap: Capture, top: int = 10) -> List[Finding]:
    print(banner("TRAFFIC SUMMARY"))

    start = time.strftime("%Y-%m-%d %H:%M:%S",
                          time.localtime(cap.first_ts)) if cap.first_ts else "n/a"
    end = time.strftime("%Y-%m-%d %H:%M:%S",
                        time.localtime(cap.last_ts)) if cap.last_ts else "n/a"
    meta = [
        ["File", os.path.basename(cap.path)],
        ["Size on disk", human_bytes(os.path.getsize(cap.path))],
        ["Packets", f"{cap.total_packets:,}"],
        ["Bytes on wire", human_bytes(cap.bytes_total)],
        ["First packet", start],
        ["Last packet", end],
        ["Duration", human_duration(cap.duration)],
        ["Avg pps", f"{cap.total_packets / cap.duration:,.1f}" if cap.duration else "n/a"],
        ["Malformed / non-IP", f"{cap.malformed} / {cap.non_ip}"],
    ]
    print("\n" + C.BOLD + "  Capture metadata" + C.RESET)
    print(render_table(["Property", "Value"], meta))

    # Protocol breakdown
    total = sum(cap.proto_counter.values()) or 1
    rows = []
    for proto, count in cap.proto_counter.most_common():
        pct = count / total * 100
        bar = "\u2588" * int(pct / 4)
        rows.append([proto, f"{count:,}", f"{pct:5.1f}%", bar])
    print("\n" + C.BOLD + "  Protocol distribution" + C.RESET)
    print(render_table(["Protocol", "Packets", "Share", ""], rows,
                       aligns=["l", "r", "r", "l"]))

    # Top talkers
    sent_pkts: Counter = Counter()
    sent_bytes: Counter = Counter()
    recv_bytes: Counter = Counter()
    peers: Dict[str, set] = defaultdict(set)
    for p in cap.packets:
        sent_pkts[p.src] += 1
        sent_bytes[p.src] += p.size
        recv_bytes[p.dst] += p.size
        peers[p.src].add(p.dst)

    rows = []
    for host, nbytes in sent_bytes.most_common(top):
        rows.append([host, f"{sent_pkts[host]:,}", human_bytes(nbytes),
                     human_bytes(recv_bytes.get(host, 0)), len(peers[host])])
    print("\n" + C.BOLD + f"  Top {top} talkers (by bytes sent)" + C.RESET)
    print(render_table(["Host", "Pkts sent", "Bytes sent", "Bytes recv", "Peers"],
                       rows, aligns=["l", "r", "r", "r", "r"]))

    # Top conversations
    convo_bytes: Counter = Counter()
    convo_pkts: Counter = Counter()
    for p in cap.packets:
        key = tuple(sorted([p.src, p.dst]))
        convo_bytes[key] += p.size
        convo_pkts[key] += 1
    rows = [[f"{a}  \u21c4  {b}", f"{convo_pkts[(a, b)]:,}", human_bytes(n)]
            for (a, b), n in convo_bytes.most_common(top)]
    print("\n" + C.BOLD + f"  Top {top} conversations" + C.RESET)
    print(render_table(["Endpoints", "Packets", "Bytes"], rows,
                       aligns=["l", "r", "r"], max_width=60))

    # Top destination ports
    port_counter: Counter = Counter()
    port_bytes: Counter = Counter()
    for p in cap.packets:
        if p.proto in ("TCP", "UDP") and p.dport:
            port_counter[(p.proto, p.dport)] += 1
            port_bytes[(p.proto, p.dport)] += p.size
    rows = [[proto, port, WELL_KNOWN.get(port, "-"), f"{n:,}",
             human_bytes(port_bytes[(proto, port)])]
            for (proto, port), n in port_counter.most_common(top)]
    print("\n" + C.BOLD + f"  Top {top} destination ports" + C.RESET)
    print(render_table(["Proto", "Port", "Service", "Packets", "Bytes"], rows,
                       aligns=["l", "r", "l", "r", "r"]))

    return []


# ──────────────────────────────────────────────────────────────────────────────
#  Module 2 - Port scan detection
# ──────────────────────────────────────────────────────────────────────────────

def module_port_scan(cap: Capture,
                     port_threshold: int = 15,
                     host_threshold: int = 15,
                     window: float = 60.0,
                     top: int = 15) -> List[Finding]:
    print(banner("PORT SCAN DETECTION"))
    findings: List[Finding] = []

    # src -> dst -> set(ports);  plus timestamps for rate calculation
    vertical: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    horizontal: Dict[Tuple[str, int], set] = defaultdict(set)   # (src, port) -> dsts
    times: Dict[str, List[float]] = defaultdict(list)
    syn_total = 0

    for p in cap.tcp_syns():
        syn_total += 1
        vertical[p.src][p.dst].add(p.dport)
        horizontal[(p.src, p.dport)].add(p.dst)
        times[p.src].append(p.ts)

    # Half-open detection: SYNs that never received a SYN/ACK
    synack = {(p.dst, p.src, p.sport) for p in cap.packets
              if p.proto == "TCP" and "S" in p.flags and "A" in p.flags}
    rst = {(p.dst, p.src, p.sport) for p in cap.packets
           if p.proto == "TCP" and "R" in p.flags}

    # --- vertical scans (one host, many ports) ---------------------------
    rows = []
    for src, dsts in vertical.items():
        for dst, ports in dsts.items():
            if len(ports) < port_threshold:
                continue
            ts_list = sorted(t for t in times[src])
            span = (ts_list[-1] - ts_list[0]) if len(ts_list) > 1 else 0.0
            rate = len(ports) / span if span > 0 else float(len(ports))
            open_ports = sorted(pt for pt in ports if (src, dst, pt) in synack)
            refused = sum(1 for pt in ports if (src, dst, pt) in rst)
            unanswered = len(ports) - len(open_ports) - refused

            sev = "HIGH" if len(ports) >= 100 else "MEDIUM"
            if rate > 50:
                sev = "CRITICAL"
            findings.append(Finding(
                module="port_scan", severity=sev,
                title=f"Vertical port scan: {len(ports)} ports on {dst}",
                src=src, dst=dst, mitre="T1046 - Network Service Discovery",
                evidence={
                    "distinct_ports": len(ports),
                    "port_range": f"{min(ports)}-{max(ports)}",
                    "duration_sec": round(span, 3),
                    "ports_per_sec": round(rate, 1),
                    "open_ports": open_ports[:25],
                    "refused": refused,
                    "unanswered": unanswered,
                    "scan_style": "stealth/half-open" if unanswered > len(ports) * 0.5
                                  else "full-connect",
                }))
            rows.append([src, dst, len(ports), f"{min(ports)}-{max(ports)}",
                         human_duration(span), f"{rate:.1f}",
                         ",".join(str(o) for o in open_ports[:6]) or "-",
                         severity_colour(sev) + sev + C.RESET])

    rows.sort(key=lambda r: -int(r[2]))
    print(f"\n  TCP SYN packets seen: {C.BOLD}{syn_total:,}{C.RESET}"
          f"   |   unique initiators: {C.BOLD}{len(vertical)}{C.RESET}")
    print("\n" + C.BOLD + "  Vertical scans (many ports \u2192 one host)" + C.RESET)
    print(render_table(["Source", "Target", "Ports", "Range", "Window",
                        "Ports/s", "Open", "Severity"],
                       rows[:top], aligns=["l", "l", "r", "l", "r", "r", "l", "l"]))

    # --- horizontal scans (one port, many hosts) -------------------------
    rows = []
    for (src, port), dsts in horizontal.items():
        if len(dsts) < host_threshold:
            continue
        sev = "HIGH" if len(dsts) >= 50 else "MEDIUM"
        findings.append(Finding(
            module="port_scan", severity=sev,
            title=f"Horizontal sweep: port {port} across {len(dsts)} hosts",
            src=src, dst=f"{len(dsts)} hosts",
            mitre="T1046 - Network Service Discovery",
            evidence={"port": port, "service": WELL_KNOWN.get(port, "unknown"),
                      "hosts_probed": len(dsts),
                      "sample_targets": sorted(dsts)[:10]}))
        rows.append([src, port, WELL_KNOWN.get(port, "-"), len(dsts),
                     ", ".join(sorted(dsts)[:3]),
                     severity_colour(sev) + sev + C.RESET])
    rows.sort(key=lambda r: -int(r[3]))
    print("\n" + C.BOLD + "  Horizontal sweeps (one port \u2192 many hosts)" + C.RESET)
    print(render_table(["Source", "Port", "Service", "Hosts", "Sample targets",
                        "Severity"], rows[:top],
                       aligns=["l", "r", "l", "r", "l", "l"]))

    if not findings:
        print(f"\n  {C.GREEN}No scanning behaviour above thresholds "
              f"({port_threshold} ports / {host_threshold} hosts).{C.RESET}")
    return findings


# ──────────────────────────────────────────────────────────────────────────────
#  Module 3 - C2 beaconing detection
# ──────────────────────────────────────────────────────────────────────────────

def _collapse_to_events(timestamps: List[float], gap: float) -> List[float]:
    """Collapse packet bursts into single 'session start' events."""
    events: List[float] = []
    last = None
    for ts in sorted(timestamps):
        if last is None or (ts - last) > gap:
            events.append(ts)
        last = ts
    return events


def module_beaconing(cap: Capture,
                     min_events: int = 6,
                     burst_gap: float = 2.0,
                     min_interval: float = 1.0,
                     max_interval: float = 86400.0,
                     score_threshold: float = 65.0,
                     top: int = 20) -> List[Finding]:
    print(banner("C2 BEACONING DETECTION"))
    findings: List[Finding] = []

    flows: Dict[Tuple[str, str, int, str], List[float]] = defaultdict(list)
    sizes: Dict[Tuple[str, str, int, str], List[int]] = defaultdict(list)
    for p in cap.packets:
        if p.proto not in ("TCP", "UDP") or not p.dport:
            continue
        key = (p.src, p.dst, p.dport, p.proto)
        flows[key].append(p.ts)
        sizes[key].append(p.size)

    candidates = []
    for key, ts_list in flows.items():
        events = _collapse_to_events(ts_list, burst_gap)
        if len(events) < min_events:
            continue
        intervals = [b - a for a, b in zip(events, events[1:])]
        if not intervals:
            continue
        mean_i = statistics.fmean(intervals)
        if mean_i < min_interval or mean_i > max_interval:
            continue

        stdev_i = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        median_i = statistics.median(intervals)
        cv = stdev_i / mean_i if mean_i else 1.0            # coefficient of variation
        mad = statistics.median([abs(i - median_i) for i in intervals])
        mad_ratio = mad / median_i if median_i else 1.0

        # Regularity score: 0-100, weighted blend of CV and MAD ratio.
        regularity = (1 - min(cv, 1.0)) * 60 + (1 - min(mad_ratio, 1.0)) * 40

        # Payload-size uniformity bonus - real beacons send near-identical sizes.
        sz = sizes[key]
        size_mean = statistics.fmean(sz)
        size_cv = (statistics.pstdev(sz) / size_mean) if size_mean else 1.0
        size_bonus = (1 - min(size_cv, 1.0)) * 10

        # More observations => more confidence.
        confidence = min(len(events) / 20.0, 1.0)
        score = min(100.0, (regularity + size_bonus) * (0.7 + 0.3 * confidence))

        if score < score_threshold:
            continue

        src, dst, dport, proto = key
        jitter_pct = cv * 100
        sev = ("CRITICAL" if score >= 90 and len(events) >= 12 else
               "HIGH" if score >= 80 else "MEDIUM")
        candidates.append((score, key, {
            "events": len(events),
            "mean_interval_sec": round(mean_i, 2),
            "median_interval_sec": round(median_i, 2),
            "stdev_sec": round(stdev_i, 3),
            "jitter_pct": round(jitter_pct, 1),
            "mad_ratio": round(mad_ratio, 3),
            "regularity_score": round(score, 1),
            "avg_packet_bytes": round(size_mean, 1),
            "size_variation_pct": round(size_cv * 100, 1),
            "total_bytes": sum(sz),
            "span": round(events[-1] - events[0], 1),
            "severity": sev,
        }))

    candidates.sort(key=lambda x: -x[0])
    rows = []
    for score, (src, dst, dport, proto), ev in candidates[:top]:
        sev = ev["severity"]
        findings.append(Finding(
            module="beaconing", severity=sev,
            title=f"Periodic callback every ~{ev['median_interval_sec']}s "
                  f"to {dst}:{dport}/{proto.lower()}",
            src=src, dst=f"{dst}:{dport}",
            mitre="T1071 - Application Layer Protocol / T1573 - Encrypted Channel",
            evidence=ev))
        rows.append([src, f"{dst}:{dport}", proto, ev["events"],
                     f"{ev['median_interval_sec']}s", f"{ev['jitter_pct']:.1f}%",
                     f"{ev['avg_packet_bytes']:.0f}",
                     human_duration(ev["span"]), f"{score:.0f}",
                     severity_colour(sev) + sev + C.RESET])

    print(f"\n  Flows examined: {C.BOLD}{len(flows):,}{C.RESET}"
          f"   |   beacon candidates: {C.BOLD}{len(candidates)}{C.RESET}"
          f"   |   score threshold: {score_threshold}")
    print("\n" + C.BOLD + "  Suspected beacons (sorted by regularity score)" + C.RESET)
    print(render_table(["Source", "Destination", "Proto", "Events", "Interval",
                        "Jitter", "Avg B", "Span", "Score", "Severity"],
                       rows, aligns=["l", "l", "l", "r", "r", "r", "r", "r", "r", "l"]))
    if not candidates:
        print(f"\n  {C.GREEN}No periodic flows exceeded the scoring threshold.{C.RESET}")
    else:
        print(f"\n  {C.DIM}Score = regularity of inter-arrival times (60%) + "
              f"median-absolute-deviation stability (40%) + payload uniformity bonus,"
              f"\n  scaled by observation count. Low jitter + fixed payload size = "
              f"automated callback.{C.RESET}")
    return findings


# ──────────────────────────────────────────────────────────────────────────────
#  Module 4 - DNS tunneling detection
# ──────────────────────────────────────────────────────────────────────────────

MULTI_TLDS = {
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za", "com.au", "com.br",
    "com.cn", "com.mx", "com.tr", "com.sg", "net.au", "org.uk", "ac.uk",
    "gov.uk", "ac.in", "edu.au", "net.in", "org.in",
}
SUSPICIOUS_QTYPES = {"TXT", "NULL", "CNAME", "MX", "SRV", "ANY"}


def registered_domain(qname: str) -> Tuple[str, str]:
    """Split FQDN into (subdomain-part, registered-domain) using a TLD heuristic."""
    labels = qname.strip(".").split(".")
    if len(labels) <= 2:
        return "", ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_TLDS and len(labels) > 3:
        return ".".join(labels[:-3]), ".".join(labels[-3:])
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def module_dns_tunneling(cap: Capture,
                         min_queries: int = 10,
                         entropy_threshold: float = 3.3,
                         length_threshold: float = 25.0,
                         score_threshold: float = 55.0,
                         top: int = 15) -> List[Finding]:
    print(banner("DNS TUNNELING / EXFILTRATION DETECTION"))
    findings: List[Finding] = []

    per_domain: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"subs": [], "entropies": [], "lengths": [], "qtypes": Counter(),
                 "clients": set(), "times": [], "servers": set(), "samples": []})

    for ts, src, qname, qtype, dst in cap.dns_queries:
        sub, dom = registered_domain(qname)
        d = per_domain[dom]
        d["clients"].add(src)
        d["servers"].add(dst)
        d["qtypes"][qtype] += 1
        d["times"].append(ts)
        if sub:
            d["subs"].append(sub)
            flat = sub.replace(".", "")
            d["entropies"].append(shannon_entropy(flat))
            d["lengths"].append(len(flat))
            if len(d["samples"]) < 3:
                d["samples"].append(qname)

    rows = []
    scored = []
    for dom, d in per_domain.items():
        nq = len(d["times"])
        if nq < min_queries or not d["entropies"]:
            continue

        avg_ent = statistics.fmean(d["entropies"])
        max_ent = max(d["entropies"])
        avg_len = statistics.fmean(d["lengths"])
        max_len = max(d["lengths"])
        uniq_subs = len(set(d["subs"]))
        uniq_ratio = uniq_subs / nq
        span = max(d["times"]) - min(d["times"])
        qps = nq / span if span > 0 else float(nq)
        sus_q = sum(c for t, c in d["qtypes"].items() if t in SUSPICIOUS_QTYPES)
        sus_ratio = sus_q / nq

        # Composite score (0-100)
        score = 0.0
        score += min(avg_ent / 4.5, 1.0) * 30           # randomness of labels
        score += min(avg_len / 40.0, 1.0) * 25          # label length
        score += uniq_ratio * 20                        # near-unique subdomains
        score += min(nq / 200.0, 1.0) * 10              # query volume
        score += sus_ratio * 10                         # TXT/NULL/CNAME heavy
        score += min(qps / 5.0, 1.0) * 5                # query rate
        score = min(score, 100.0)

        if score < score_threshold and not (
                avg_ent >= entropy_threshold and avg_len >= length_threshold):
            continue

        sev = ("CRITICAL" if score >= 80 else "HIGH" if score >= 65 else "MEDIUM")
        est_bytes = int(sum(d["lengths"]) * 0.6)  # base32/hex payload ≈ 60% density
        scored.append((score, dom))
        findings.append(Finding(
            module="dns_tunneling", severity=sev,
            title=f"Probable DNS tunneling over {dom}",
            src=", ".join(sorted(d["clients"])[:3]), dst=dom,
            mitre="T1071.004 - DNS / T1048.003 - Exfil Over Unencrypted Protocol",
            evidence={
                "queries": nq, "unique_subdomains": uniq_subs,
                "unique_ratio": round(uniq_ratio, 3),
                "avg_entropy_bits_per_char": round(avg_ent, 2),
                "max_entropy": round(max_ent, 2),
                "avg_subdomain_len": round(avg_len, 1), "max_subdomain_len": max_len,
                "qtype_breakdown": dict(d["qtypes"]),
                "suspicious_qtype_ratio": round(sus_ratio, 2),
                "queries_per_sec": round(qps, 2),
                "duration_sec": round(span, 1),
                "clients": sorted(d["clients"]),
                "estimated_exfil_bytes": est_bytes,
                "sample_queries": d["samples"],
                "score": round(score, 1),
            }))
        rows.append([dom, nq, uniq_subs, f"{avg_ent:.2f}", f"{avg_len:.0f}",
                     max_len, d["qtypes"].most_common(1)[0][0],
                     human_bytes(est_bytes), f"{score:.0f}",
                     severity_colour(sev) + sev + C.RESET])

    rows.sort(key=lambda r: -float(r[8]))
    print(f"\n  DNS queries parsed: {C.BOLD}{len(cap.dns_queries):,}{C.RESET}"
          f"   |   distinct domains: {C.BOLD}{len(per_domain):,}{C.RESET}")
    print("\n" + C.BOLD + "  Suspicious domains" + C.RESET)
    print(render_table(["Registered domain", "Queries", "Uniq subs", "Entropy",
                        "Avg len", "Max len", "Top type", "Est. exfil", "Score",
                        "Severity"], rows[:top],
                       aligns=["l", "r", "r", "r", "r", "r", "l", "r", "r", "l"]))

    for f in findings[:5]:
        if f.evidence.get("sample_queries"):
            print(f"\n  {C.DIM}Sample queries for {f.dst}:{C.RESET}")
            for q in f.evidence["sample_queries"]:
                print(f"    {C.YELLOW}{q[:110]}{C.RESET}")

    if not findings:
        print(f"\n  {C.GREEN}No domains matched the tunneling profile "
              f"(entropy \u2265 {entropy_threshold}, avg label \u2265 "
              f"{length_threshold} chars).{C.RESET}")
    return findings


# ──────────────────────────────────────────────────────────────────────────────
#  Module 5 - Cleartext credential exposure
# ──────────────────────────────────────────────────────────────────────────────

CRED_KEYS = ("password", "passwd", "pass", "pwd", "user", "username", "uname",
             "login", "email", "userid", "user_id", "secret", "token", "apikey",
             "api_key", "auth", "session", "credential")
SECRET_KEYS = ("password", "passwd", "pass", "pwd", "secret", "token",
               "apikey", "api_key", "credential")

FORM_RE = re.compile(
    r"(?i)\b(" + "|".join(CRED_KEYS) + r")\s*=\s*([^&\s\"';]{1,128})")
JSON_RE = re.compile(
    r"(?i)\"(" + "|".join(CRED_KEYS) + r")\"\s*:\s*\"([^\"]{1,128})\"")
BASIC_RE = re.compile(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]+)")
BEARER_RE = re.compile(rb"(?i)authorization:\s*bearer\s+([A-Za-z0-9\-._~+/=]+)")
HOST_RE = re.compile(rb"(?i)\r\nhost:\s*([^\r\n]+)")
REQLINE_RE = re.compile(rb"^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(\S+)\s+HTTP/1\.[01]")
COOKIE_RE = re.compile(rb"(?i)\r\ncookie:\s*([^\r\n]{1,200})")


def mask(value: str, reveal: bool) -> str:
    if reveal or len(value) <= 2:
        return value
    return value[:2] + "*" * min(len(value) - 2, 10)


def module_credentials(cap: Capture, reveal: bool = False,
                       top: int = 40) -> List[Finding]:
    print(banner("CLEARTEXT CREDENTIAL EXPOSURE"))
    findings: List[Finding] = []
    rows = []
    # Keyed on the sorted endpoint pair so both directions reassemble together -
    # the server sends "login:" / "Password:" and the client sends the answers.
    telnet_sessions: Dict[Tuple[str, str], List[Tuple[float, str, bytes]]] = \
        defaultdict(list)

    def add(proto: str, p: PacketRecord, ctype: str, user: str, secret: str,
            note: str = "", sev: str = "HIGH") -> None:
        findings.append(Finding(
            module="credentials", severity=sev,
            title=f"{proto} cleartext {ctype}",
            src=f"{p.src}:{p.sport}", dst=f"{p.dst}:{p.dport}",
            mitre="T1040 - Network Sniffing / T1552.001 - Credentials In Files",
            evidence={"protocol": proto, "type": ctype,
                      "username": user, "secret": mask(secret, reveal),
                      "secret_length": len(secret), "context": note,
                      "timestamp": time.strftime("%H:%M:%S", time.localtime(p.ts))}))
        rows.append([time.strftime("%H:%M:%S", time.localtime(p.ts)), proto,
                     f"{p.src} \u2192 {p.dst}:{p.dport}", ctype,
                     user or "-", mask(secret, reveal) or "-",
                     severity_colour(sev) + sev + C.RESET])

    for p in cap.packets:
        if not p.payload:
            if p.proto == "TCP" and p.dport == 23:
                pass
            continue
        raw = p.payload
        dport, sport = p.dport, p.sport

        # ---------- HTTP ----------
        if dport in HTTP_PORTS or sport in HTTP_PORTS:
            m = BASIC_RE.search(raw)
            if m:
                try:
                    decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
                    u, _, pw = decoded.partition(":")
                except Exception:  # noqa: BLE001
                    u, pw = "?", "?"
                host = HOST_RE.search(raw)
                add("HTTP", p, "Basic auth header", u, pw,
                    host.group(1).decode("utf-8", "replace") if host else "",
                    sev="CRITICAL")
            m = BEARER_RE.search(raw)
            if m:
                add("HTTP", p, "Bearer token", "-",
                    m.group(1).decode("utf-8", "replace"), sev="HIGH")

            req = REQLINE_RE.match(raw)
            if req and req.group(1) in (b"POST", b"PUT", b"PATCH"):
                head, _, body = raw.partition(b"\r\n\r\n")
                text = body.decode("utf-8", "replace")
                path = req.group(2).decode("utf-8", "replace")
                found = {}
                for rx in (FORM_RE, JSON_RE):
                    for key, val in rx.findall(text):
                        found[key.lower()] = val
                if found:
                    user = next((v for k, v in found.items()
                                 if k in ("user", "username", "uname", "login",
                                          "email", "userid", "user_id")), "")
                    secret = next((v for k, v in found.items()
                                   if k in SECRET_KEYS), "")
                    if user or secret:
                        add("HTTP", p, f"POST body ({path[:40]})",
                            user, secret, note=",".join(found.keys()),
                            sev="CRITICAL" if secret else "MEDIUM")
            if req and req.group(1) == b"GET":
                q = req.group(2).decode("utf-8", "replace")
                if "?" in q:
                    found = dict(FORM_RE.findall(q))
                    secret = next((v for k, v in found.items()
                                   if k.lower() in SECRET_KEYS), "")
                    if secret:
                        add("HTTP", p, "Credential in GET query string",
                            next(iter(found.values()), ""), secret, sev="CRITICAL")

        # ---------- FTP ----------
        elif dport == 21 or sport == 21:
            txt = raw.decode("utf-8", "replace").strip()
            for line in txt.splitlines():
                up = line.upper()
                if up.startswith("USER "):
                    add("FTP", p, "USER command", line[5:].strip(), "", sev="MEDIUM")
                elif up.startswith("PASS "):
                    add("FTP", p, "PASS command", "", line[5:].strip(),
                        sev="CRITICAL")

        # ---------- Telnet ----------
        elif dport == 23 or sport == 23:
            pair = (p.src, p.dst) if p.src < p.dst else (p.dst, p.src)
            telnet_sessions[pair].append((p.ts, p.src, raw))

        # ---------- SMTP / POP3 / IMAP ----------
        elif dport in (25, 110, 143, 587) or sport in (25, 110, 143, 587):
            proto = {25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP"}.get(
                dport if dport in (25, 110, 143, 587) else sport, "MAIL")
            txt = raw.decode("utf-8", "replace").strip()
            for line in txt.splitlines():
                up = line.upper()
                if up.startswith("USER "):
                    add(proto, p, "USER command", line[5:].strip(), "", sev="MEDIUM")
                elif up.startswith("PASS "):
                    add(proto, p, "PASS command", "", line[5:].strip(), sev="CRITICAL")
                elif up.startswith("LOGIN "):
                    parts = line.split()
                    if len(parts) >= 3:
                        add(proto, p, "IMAP LOGIN", parts[1], parts[2],
                            sev="CRITICAL")
                elif up.startswith("AUTH LOGIN") or up.startswith("AUTH PLAIN"):
                    add(proto, p, "AUTH LOGIN negotiation", "", "",
                        note="base64 credentials follow", sev="MEDIUM")
                elif re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", line.strip()):
                    try:
                        dec = base64.b64decode(line.strip()).decode("utf-8", "replace")
                        if dec.isprintable() and len(dec) < 80:
                            add(proto, p, "base64 AUTH blob", "", dec, sev="HIGH")
                    except Exception:  # noqa: BLE001
                        pass

    # ---------- Telnet session reassembly ----------
    for (a, b), chunks in telnet_sessions.items():
        chunks.sort(key=lambda c: c[0])
        first_ts = chunks[0][0]
        stream = b"".join(c[2] for c in chunks)
        # Strip telnet IAC option negotiation and non-printables before matching.
        stream = re.sub(rb"\xff[\xfb-\xfe].", b"", stream)
        text = re.sub(rb"[^\x20-\x7e\r\n]", b"", stream).decode("ascii", "replace")

        m = re.search(r"(?i)(?:login|username)\s*:\s*([^\s:]+)", text)
        user = m.group(1) if m else ""
        m2 = re.search(r"(?i)password\s*:\s*([^\s:]+)", text)
        secret = m2.group(1) if m2 else ""
        # Guard against matching the next prompt instead of the typed answer.
        if user.lower().rstrip(":") in ("password", "passwd"):
            user = ""

        sev = "CRITICAL" if secret else "HIGH"
        client, server = (a, b)
        findings.append(Finding(
            module="credentials", severity=sev,
            title="Telnet session in cleartext",
            src=client, dst=f"{server}:23", mitre="T1040 - Network Sniffing",
            evidence={"protocol": "TELNET", "type": "unencrypted session",
                      "username": user, "secret": mask(secret, reveal),
                      "bytes_captured": len(stream),
                      "transcript_preview": text[:300],
                      "timestamp": time.strftime("%H:%M:%S",
                                                 time.localtime(first_ts))}))
        rows.append([time.strftime("%H:%M:%S", time.localtime(first_ts)),
                     "TELNET", f"{a} \u21c4 {b}:23", "session transcript",
                     user or "-", mask(secret, reveal) or "(see transcript)",
                     severity_colour(sev) + sev + C.RESET])

    print(f"\n  Payload-bearing packets inspected: "
          f"{C.BOLD}{sum(1 for p in cap.packets if p.payload):,}{C.RESET}")
    print("\n" + C.BOLD + "  Exposed credentials" + C.RESET)
    print(render_table(["Time", "Proto", "Flow", "Type", "Username", "Secret",
                        "Severity"], rows[:top],
                       aligns=["l", "l", "l", "l", "l", "l", "l"]))
    if rows and not reveal:
        print(f"\n  {C.DIM}Secrets are masked. Re-run with --show-secrets "
              f"to display full values.{C.RESET}")
    if not rows:
        print(f"\n  {C.GREEN}No cleartext credentials observed.{C.RESET}")
    return findings


# ──────────────────────────────────────────────────────────────────────────────
#  Module 6 - Passive vulnerability identification
# ──────────────────────────────────────────────────────────────────────────────
#
# This mirrors how real passive vulnerability tools work (Nessus's Passive
# Vulnerability Scanner, p0f, RockNSM/Zeek's software.log): never send a
# single probe packet, just read the version strings services voluntarily
# announce in normal traffic - an SSH banner, an FTP welcome message, an
# HTTP Server header, a TLS ClientHello's protocol version - and match them
# against a curated table of known-vulnerable releases. It is a genuine,
# well-established vulnerability-assessment technique; it is just driven
# entirely off a recording instead of live probes.

# (regex pattern, CVE id, human name, severity, description, CVSS v3 base
# score, one-line remediation). CVSS scores are the published NVD base
# scores for each CVE, not something computed here.
VULN_SIGNATURES: List[Tuple[re.Pattern, str, str, str, str, float, str]] = [
    (re.compile(rb"vsftpd 2\.3\.4", re.IGNORECASE), "CVE-2011-2523",
     "vsftpd 2.3.4 backdoor",
     "CRITICAL",
     "This exact build contains a maliciously inserted backdoor triggered "
     "by a ':)' in the username, giving a remote root shell.",
     9.8, "Upgrade to vsftpd 3.x from the official repository immediately; "
          "treat this host as compromised if 2.3.4 was ever internet-facing."),
    (re.compile(rb"ProFTPD 1\.3\.3[a-c]?", re.IGNORECASE), "CVE-2010-4221",
     "ProFTPD 1.3.3c backdoor",
     "CRITICAL",
     "A trojaned source release of ProFTPD 1.3.3c shipped with a backdoor "
     "giving unauthenticated remote command execution.",
     9.8, "Upgrade to a current ProFTPD release built from the verified "
          "official source; do not trust the existing binary."),
    (re.compile(rb"OpenSSH[_-](4\.[0-9]|5\.[0-3])(?:[^0-9]|$)", re.IGNORECASE), "CVE-2008-5161",
     "Outdated OpenSSH (< 5.4)",
     "MEDIUM",
     "Old OpenSSH releases are missing years of hardening; some CBC-mode "
     "builds are also vulnerable to a plaintext-recovery attack.",
     5.9, "Upgrade to the latest OpenSSH from your distro's package manager "
          "and disable CBC ciphers in sshd_config."),
    (re.compile(rb"OpenSSH[_-]6\.6", re.IGNORECASE), "CVE-2016-6210",
     "OpenSSH 6.6 user enumeration",
     "MEDIUM",
     "Response-time difference during authentication lets a remote "
     "attacker enumerate valid usernames.",
     5.3, "Upgrade OpenSSH to 7.3+ where the timing side-channel was fixed."),
    (re.compile(rb"Apache/2\.4\.49", re.IGNORECASE), "CVE-2021-41773",
     "Apache HTTP Server 2.4.49 path traversal / RCE",
     "CRITICAL",
     "A path normalisation flaw allows path traversal and, if CGI is "
     "enabled, remote code execution. One of the most exploited CVEs of 2021.",
     9.8, "Upgrade to Apache 2.4.51 or later immediately; this was mass "
          "-exploited within days of disclosure."),
    (re.compile(rb"Apache/2\.4\.50\b", re.IGNORECASE), "CVE-2021-42013",
     "Apache HTTP Server 2.4.50 path traversal / RCE",
     "CRITICAL",
     "The fix for CVE-2021-41773 was incomplete; 2.4.50 remains exploitable "
     "via a second, similar path traversal sequence.",
     9.8, "Upgrade to Apache 2.4.51 or later - 2.4.50 is not sufficient."),
    (re.compile(rb"Apache/2\.2\.", re.IGNORECASE), "CVE-2017-15715",
     "Apache HTTP Server 2.2.x (end-of-life branch)",
     "MEDIUM",
     "The 2.2.x branch is end-of-life and unpatched against multiple "
     "later disclosures, including a mod_mime regex bypass.",
     6.5, "Upgrade to a currently supported Apache 2.4.x release; 2.2.x "
          "receives no security patches at all."),
    (re.compile(rb"OpenSSL/1\.0\.1[a-f]?\b", re.IGNORECASE), "CVE-2014-0160",
     "OpenSSL Heartbleed",
     "CRITICAL",
     "Affected OpenSSL builds leak up to 64KB of process memory per "
     "request - private keys, session cookies, credentials - with no "
     "trace left in logs.",
     7.5, "Upgrade to OpenSSL 1.0.1g or later and reissue every certificate "
          "and secret that touched this host - assume they were read."),
    (re.compile(rb"Microsoft-IIS/6\.0", re.IGNORECASE), "CVE-2017-7269",
     "IIS 6.0 WebDAV buffer overflow",
     "CRITICAL",
     "The ScStoragePathFromUrl function in the WebDAV service overflows a "
     "buffer, giving unauthenticated remote code execution.",
     9.8, "IIS 6.0 is end-of-life on an end-of-life OS (Server 2003) - "
          "migrate the workload to a supported IIS/Windows Server version."),
    (re.compile(rb"Server: nginx/1\.(?:[0-9]|1[0-6])\.", re.IGNORECASE), "CVE-2017-7529",
     "Outdated nginx (< 1.13.3) integer overflow",
     "MEDIUM",
     "An integer overflow in range filter handling can leak worker "
     "process memory or crash the worker.",
     7.5, "Upgrade to nginx 1.13.3 or later, or 1.12.1+ on the stable branch."),
]

BANNER_PORTS = {21: "FTP", 22: "SSH", 25: "SMTP", 110: "POP3", 143: "IMAP"}
# (name, severity, description, CVSS, remediation) per (major, minor) TLS
# record version seen in a ClientHello.
TLS_VERSION_NAMES = {
    (3, 0): ("SSLv3", "CRITICAL",
            "Broken since the POODLE attack (CVE-2014-3566); padding "
            "oracle allows plaintext recovery.",
            3.4, "Disable SSLv3 entirely; it has no legitimate use in 2026."),
    (3, 1): ("TLS 1.0", "MEDIUM",
            "Deprecated by RFC 8996; vulnerable to the BEAST attack under "
            "some cipher configurations.",
            4.3, "Disable TLS 1.0 server-side; enforce TLS 1.2 as the floor."),
    (3, 2): ("TLS 1.1", "LOW",
            "Deprecated by RFC 8996; no known critical break but offers no "
            "modern cipher suites.",
            2.6, "Disable TLS 1.1; enforce TLS 1.2 as the floor."),
}


def module_vuln_scan(cap: Capture, top: int = 30) -> List[Finding]:
    print(banner("PASSIVE VULNERABILITY IDENTIFICATION"))
    findings: List[Finding] = []
    rows: List[List[Any]] = []
    seen: set = set()  # (host, port, cve) - report each exposure once

    def add(host: str, port: int, service: str, banner_text: str,
            cve: str, name: str, sev: str, desc: str, cvss: float,
            fix: str) -> None:
        key = (host, port, cve)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            module="vuln_scan", severity=sev,
            title=f"{name} ({cve}, CVSS {cvss})" if cve.startswith("CVE")
                  else f"{name} (CVSS {cvss})",
            src=host, dst=f"port {port}/{service}",
            mitre="T1592.002 - Software Discovery (passive)",
            evidence={"host": host, "port": port, "service": service,
                      "banner": banner_text[:120], "cve": cve, "cvss": cvss,
                      "description": desc, "remediation": fix}))
        rows.append([host, f"{port}/{service}", cve, name[:32], f"{cvss:.1f}",
                     severity_colour(sev) + sev + C.RESET])

    # ---------- 1. banner-based signature matching ----------
    banner_seen: Dict[Tuple[str, int], bytes] = {}
    for p in cap.packets:
        if not p.payload:
            continue
        service = BANNER_PORTS.get(p.sport) or (
            "HTTP" if p.sport in HTTP_PORTS else None)
        if service:
            key = (p.src, p.sport)
            if key not in banner_seen:
                banner_seen[key] = p.payload
            else:
                banner_seen[key] += p.payload[:200]

    for (host, port), blob in banner_seen.items():
        service = BANNER_PORTS.get(port, "HTTP")
        first_line = blob.split(b"\r\n", 1)[0][:120]
        for pattern, cve, name, sev, desc, cvss, fix in VULN_SIGNATURES:
            if pattern.search(blob):
                add(host, port, service,
                    first_line.decode("utf-8", "replace"), cve, name, sev,
                    desc, cvss, fix)

    # ---------- 2. deprecated TLS version from the ClientHello ----------
    tls_seen: set = set()
    for p in cap.packets:
        if p.proto != "TCP" or not p.payload or p.dport != 443:
            continue
        raw = p.payload
        # TLS record header: type(1) version(2) length(2) ; handshake: type(1) ...
        if len(raw) < 11 or raw[0] != 0x16 or raw[5] != 0x01:
            continue  # not a ClientHello record
        major, minor = raw[9], raw[10]
        info = TLS_VERSION_NAMES.get((major, minor))
        if not info:
            continue
        name, sev, desc, cvss, fix = info
        key = (p.src, p.dst)
        if key in tls_seen:
            continue
        tls_seen.add(key)
        add(p.dst, 443, "TLS", f"ClientHello advertises {name}",
            f"weak-tls-{minor}", f"Deprecated protocol offered: {name}",
            sev, desc, cvss, fix)

    rows.sort(key=lambda r: SEVERITY_ORDER.get(
        re.sub(r"\x1b\[[0-9;]*m", "", r[5]), 9))
    print(f"\n  Service banners fingerprinted: {C.BOLD}{len(banner_seen):,}{C.RESET}"
          f"   |   TLS handshakes inspected: {C.BOLD}{len(tls_seen):,}{C.RESET}")
    print("\n" + C.BOLD + "  Known-vulnerable software & weak configuration" + C.RESET)
    print(render_table(["Host", "Port/Service", "CVE / ID", "Issue", "CVSS",
                        "Severity"], rows[:top],
                       aligns=["l", "l", "l", "l", "r", "l"]))
    if findings:
        print("\n" + C.BOLD + "  Remediation" + C.RESET)
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9))[:8]:
            print(f"    {C.DIM}{f.evidence['host']}:{C.RESET} "
                  f"{f.evidence['remediation']}")
    if not findings:
        print(f"\n  {C.GREEN}No known-vulnerable banners or deprecated TLS "
              f"versions observed in this capture.{C.RESET}")
    else:
        print(f"\n  {C.DIM}Detection method: passive banner/handshake "
              f"fingerprinting against a curated signature table - the same "
              f"core technique behind Nessus's Passive Vulnerability Scanner "
              f"and p0f. No packets were sent; everything above came from "
              f"what the services announced on their own.{C.RESET}")
    return findings


# ──────────────────────────────────────────────────────────────────────────────
#  Reporting
# ──────────────────────────────────────────────────────────────────────────────

def print_executive_summary(findings: List[Finding], cap: Capture) -> None:
    print(banner("EXECUTIVE SUMMARY"))
    if not findings:
        print(f"\n  {C.GREEN}{C.BOLD}No detections. Capture looks clean against "
              f"the configured rule set.{C.RESET}\n")
        return

    by_sev = Counter(f.severity for f in findings)
    by_mod = Counter(f.module for f in findings)
    rows = [[sev, by_sev.get(sev, 0)] for sev in
            ("CRITICAL", "HIGH", "MEDIUM", "LOW") if by_sev.get(sev)]
    print("\n" + C.BOLD + "  Findings by severity" + C.RESET)
    print(render_table(["Severity", "Count"], rows, aligns=["l", "r"]))

    rows = [[m.replace("_", " ").title(), n] for m, n in by_mod.most_common()]
    print("\n" + C.BOLD + "  Findings by module" + C.RESET)
    print(render_table(["Module", "Count"], rows, aligns=["l", "r"]))

    by_pyr = Counter(f.pyramid for f in findings if f.pyramid_tier)
    if by_pyr:
        rows = sorted(
            ([p, n] for p, n in by_pyr.items()),
            key=lambda r: -int(r[0].split("tier ")[1].split("/")[0]))
        print("\n" + C.BOLD + "  Findings by Pyramid of Pain tier "
              "(higher = costlier for the attacker to evade)" + C.RESET)
        print(render_table(["Pyramid Level", "Count"], rows, aligns=["l", "r"]))

    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    print("\n" + C.BOLD + "  Prioritised detections" + C.RESET)
    rows = [[severity_colour(f.severity) + f.severity + C.RESET,
             f.module.replace("_", " "), f.title, f.src or "-", f.dst or "-"]
            for f in ordered[:25]]
    print(render_table(["Severity", "Module", "Detection", "Source", "Target"],
                       rows, max_width=52))
    print()


IOC_IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def export_iocs(findings: List[Finding], path: str) -> int:
    """Pull every distinct IP/domain indicator out of the findings and write
    a flat CSV - the kind of artifact you'd hand to a threat-intel team or
    paste into a ticket, rather than making them re-read the full report."""
    best: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def consider(indicator: str, itype: str, f: Finding) -> None:
        key = (indicator, itype)
        rank = SEVERITY_ORDER.get(f.severity, 9)
        cur = best.get(key)
        if cur is None or rank < cur["_rank"]:
            best[key] = {"indicator": indicator, "type": itype,
                        "severity": f.severity, "module": f.module,
                        "pyramid_level": f.pyramid or "Unclassified",
                        "example_finding": f.title, "_rank": rank}

    for f in findings:
        for field_val in (f.src, f.dst):
            for ip in IOC_IP_RE.findall(field_val or ""):
                consider(ip, "ip", f)
        if f.module == "dns_tunneling" and f.dst:
            consider(f.dst, "domain", f)

    if not best:
        return 0

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "indicator", "type", "severity", "module", "pyramid_level",
            "example_finding"])
        writer.writeheader()
        for row in sorted(best.values(), key=lambda r: r["_rank"]):
            row.pop("_rank", None)
            writer.writerow(row)
    return len(best)


def write_json_report(path: str, findings: List[Finding], cap: Capture,
                      args: argparse.Namespace) -> None:
    report = {
        "tool": "pcap_analyzer",
        "version": "1.0.0",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "capture": {
            "file": os.path.abspath(cap.path),
            "packets": cap.total_packets,
            "bytes": cap.bytes_total,
            "first_packet_utc": (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime(cap.first_ts))
                                 if cap.first_ts else None),
            "duration_sec": round(cap.duration, 3),
            "protocol_counts": dict(cap.proto_counter),
        },
        "thresholds": {
            "scan_ports": args.scan_ports, "scan_hosts": args.scan_hosts,
            "beacon_min_events": args.beacon_events,
            "beacon_score": args.beacon_score,
            "dns_entropy": args.dns_entropy, "dns_score": args.dns_score,
        },
        "summary": dict(Counter(f.severity for f in findings)),
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"{C.GREEN}[+] JSON report written to {path} "
          f"({len(findings)} findings){C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
#  Patch planning and remediation check
# ──────────────────────────────────────────────────────────────────────────────

def patch_target(cvss: float) -> Tuple[str, str]:
    """Map a CVSS base score to a patch priority and an example patch window."""
    if cvss >= 9.0:
        return "P1", "within 72 hours"
    if cvss >= 7.0:
        return "P2", "within 7 days"
    if cvss >= 4.0:
        return "P3", "within 30 days"
    return "P4", "next maintenance cycle"


def build_patch_plan(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Order the vulnerability findings into a patch list, worst CVSS first."""
    plan: List[Dict[str, Any]] = []
    for f in findings:
        if f.module != "vuln_scan":
            continue
        cvss = float(f.evidence.get("cvss", 0.0))
        priority, window = patch_target(cvss)
        plan.append({
            "priority": priority, "host": f.evidence.get("host", f.src),
            "service": f"{f.evidence.get('port')}/{f.evidence.get('service')}",
            "id": f.evidence.get("cve", ""), "cvss": cvss,
            "severity": f.severity, "window": window,
            "fix": f.evidence.get("remediation", "")})
    plan.sort(key=lambda r: (-r["cvss"], r["host"], r["id"]))
    return plan


def module_patch_plan(findings: List[Finding]) -> List[Dict[str, Any]]:
    import textwrap
    print(banner("PATCH PLAN"))
    plan = build_patch_plan(findings)
    if not plan:
        print(f"\n  {C.GREEN}No known-vulnerable software or deprecated TLS "
              f"versions to patch.{C.RESET}")
        return plan
    rows = [[i, r["priority"], r["host"], r["service"], r["id"],
             f"{r['cvss']:.1f}", r["window"]] for i, r in enumerate(plan, 1)]
    print("\n" + C.BOLD + "  Patch list, worst first" + C.RESET)
    print(render_table(["#", "Priority", "Host", "Service", "CVE / ID", "CVSS",
                        "Patch window"], rows,
                       aligns=["r", "l", "l", "l", "l", "r", "l"]))
    print("\n" + C.BOLD + "  Fixes" + C.RESET)
    for i, r in enumerate(plan, 1):
        print(textwrap.fill(f"{i}. {r['host']} {r['service']}: {r['fix']}",
                            width=100, initial_indent="    ",
                            subsequent_indent="       "))
    note = ("Patch windows are example timelines by CVSS band (P1 9.0 and "
            "above, P2 7.0-8.9, P3 4.0-6.9, P4 below 4.0). Set them to your "
            "own policy. After patching, capture the traffic again and confirm "
            "the fix with --compare.")
    print("\n" + C.DIM + textwrap.fill(note, width=100, initial_indent="  ",
                                       subsequent_indent="  ") + C.RESET)
    return plan


def _finding_key(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (f.get("module", ""), f.get("src", ""), f.get("dst", ""),
            f.get("title", ""))


def compare_reports(before_path: str,
                    after_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """Compare two --json reports: which findings were resolved, which remain
    and which are new. This is the verification step after patching."""
    def load(path: str) -> Dict[Tuple[str, str, str, str], Dict[str, Any]]:
        try:
            with open(path, encoding="utf-8") as fh:
                items = json.load(fh).get("findings", [])
        except (OSError, ValueError) as exc:
            sys.exit(f"[!] Could not read report {path}: {exc}")
        return {_finding_key(f): f for f in items}

    before, after = load(before_path), load(after_path)
    return {"resolved": [f for k, f in before.items() if k not in after],
            "remaining": [f for k, f in after.items() if k in before],
            "new": [f for k, f in after.items() if k not in before]}


def print_comparison(result: Dict[str, List[Dict[str, Any]]],
                     before_path: str, after_path: str) -> None:
    print(banner("REMEDIATION CHECK"))
    print(f"\n  Before: {C.BOLD}{before_path}{C.RESET}"
          f"   After: {C.BOLD}{after_path}{C.RESET}")
    rows = [["Resolved", len(result["resolved"])],
            ["Still present", len(result["remaining"])],
            ["New", len(result["new"])]]
    print("\n" + C.BOLD + "  Summary" + C.RESET)
    print(render_table(["Result", "Findings"], rows, aligns=["l", "r"]))
    earlier = len(result["resolved"]) + len(result["remaining"])
    if earlier:
        pct = len(result["resolved"]) / earlier * 100
        print(f"\n  {pct:.0f}% of the {earlier} earlier findings are gone.")
    for key, label in (("remaining", "Still present (not fixed)"),
                       ("new", "New since the earlier report"),
                       ("resolved", "Resolved")):
        items = sorted(result[key],
                       key=lambda f: SEVERITY_ORDER.get(f.get("severity", ""), 9))
        if not items:
            continue
        rows = [[f.get("severity", ""), f.get("module", "").replace("_", " "),
                 f.get("title", ""), f.get("src", "") or "-",
                 f.get("dst", "") or "-"] for f in items]
        print("\n" + C.BOLD + f"  {label}" + C.RESET)
        print(render_table(["Severity", "Module", "Finding", "Source", "Target"],
                           rows, max_width=52))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcap_analyzer.py",
        description="Offline PCAP threat-hunting tool for SOC triage "
                    "(port scans, C2 beaconing, DNS tunneling, cleartext "
                    "creds, passive vulnerability ID).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s -r capture.pcap --all
  %(prog)s -r capture.pcap --scan --beacon --json findings.json
  %(prog)s -r capture.pcap --dns --dns-entropy 3.0 --dns-score 45
  %(prog)s -r capture.pcap --creds --show-secrets
  %(prog)s -r big.pcap --all --max-packets 500000 --no-color
  %(prog)s -r capture.pcap --patch-plan
  %(prog)s --compare before.json after.json
""")
    p.add_argument("-r", "--pcap", "--read", dest="pcap", required=False,
                   metavar="FILE", help="path to .pcap / .pcapng file "
                                        "(required unless --compare is used)")
    p.add_argument("--compare", nargs=2, metavar=("BEFORE_JSON", "AFTER_JSON"),
                   help="compare two --json reports: which findings were "
                        "resolved, which remain, which are new (no pcap needed)")

    mods = p.add_argument_group("detection modules")
    mods.add_argument("--summary", action="store_true",
                      help="capture overview, protocol mix, top talkers")
    mods.add_argument("--scan", action="store_true", help="port scan detection")
    mods.add_argument("--beacon", action="store_true", help="C2 beaconing detection")
    mods.add_argument("--dns", action="store_true", help="DNS tunneling detection")
    mods.add_argument("--creds", action="store_true",
                      help="cleartext credential exposure")
    mods.add_argument("--vuln", action="store_true",
                      help="passive vulnerability identification "
                           "(banner/TLS-version signature matching)")
    mods.add_argument("--patch-plan", dest="patch_plan", action="store_true",
                      help="prioritised patch list built from the "
                           "vulnerability findings (implies --vuln)")
    mods.add_argument("--all", action="store_true", help="run every module")

    tun = p.add_argument_group("tuning")
    tun.add_argument("--scan-ports", type=int, default=15, metavar="N",
                     help="distinct ports per target to flag a vertical scan (default 15)")
    tun.add_argument("--scan-hosts", type=int, default=15, metavar="N",
                     help="distinct hosts per port to flag a sweep (default 15)")
    tun.add_argument("--beacon-events", type=int, default=6, metavar="N",
                     help="minimum callbacks needed to score a flow (default 6)")
    tun.add_argument("--beacon-gap", type=float, default=2.0, metavar="SEC",
                     help="packets closer than this collapse into one event (default 2.0)")
    tun.add_argument("--beacon-score", type=float, default=65.0, metavar="N",
                     help="regularity score 0-100 required to report (default 65)")
    tun.add_argument("--beacon-max-interval", type=float, default=86400.0,
                     metavar="SEC", help="ignore intervals longer than this (default 86400)")
    tun.add_argument("--dns-min-queries", type=int, default=10, metavar="N",
                     help="minimum queries per domain to evaluate (default 10)")
    tun.add_argument("--dns-entropy", type=float, default=3.3, metavar="BITS",
                     help="avg Shannon entropy per char to flag (default 3.3)")
    tun.add_argument("--dns-length", type=float, default=25.0, metavar="N",
                     help="avg subdomain length to flag (default 25)")
    tun.add_argument("--dns-score", type=float, default=55.0, metavar="N",
                     help="composite DNS score required to report (default 55)")

    out = p.add_argument_group("output")
    out.add_argument("--top", type=int, default=10, metavar="N",
                     help="rows shown in ranked tables (default 10)")
    out.add_argument("--json", dest="json_out", metavar="FILE",
                     help="write full findings to a JSON file")
    out.add_argument("--export-iocs", dest="export_iocs", metavar="FILE",
                     help="write distinct IPs/domains from findings to a "
                          "CSV, for threat-intel handoff")
    out.add_argument("--show-secrets", action="store_true",
                     help="print recovered passwords unmasked")
    out.add_argument("--filter-src", default="", metavar="IP",
                     help="only analyse packets from this source IP")
    out.add_argument("--max-packets", type=int, default=0, metavar="N",
                     help="stop after N packets (useful on huge captures)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="suppress the parser progress lines")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        C.disable()

    if args.compare:
        result = compare_reports(*args.compare)
        print_comparison(result, *args.compare)
        return 1 if (result["remaining"] or result["new"]) else 0
    if not args.pcap:
        parser.error("-r/--pcap is required unless --compare is used")

    if args.all:
        args.summary = args.scan = args.beacon = args.dns = args.creds = \
            args.vuln = True
    if args.patch_plan:
        args.vuln = True
    if not any([args.summary, args.scan, args.beacon, args.dns, args.creds,
               args.vuln]):
        args.summary = True
        print(f"{C.DIM}[*] No module selected - defaulting to --summary. "
              f"Use --all to run everything.{C.RESET}")

    print(f"{C.BOLD}{C.CYAN}")
    print(r"   ___  _________   ___    ___                __                    ")
    print(r"  / _ \/ ___/ _ | / _ \  / _ | ___  ___ _/ / __ ______ ___ ____   ")
    print(r" / ___/ /__/ __ |/ ___/ / __ |/ _ \/ _ `/ / // /_  / -_) __/    ")
    print(r"/_/   \___/_/ |_/_/    /_/ |_/_//_/\_,_/_/\_, / /___\__/_/       ")
    print(f"                                         /___/   v1.0{C.RESET}\n")

    cap = Capture(args.pcap, bpf_src=args.filter_src,
                  max_packets=args.max_packets).load(verbose=not args.quiet)

    if cap.total_packets == 0:
        print(f"{C.RED}[!] Capture contains no readable packets.{C.RESET}")
        return 2

    findings: List[Finding] = []
    if args.summary:
        findings += module_summary(cap, top=args.top)
    if args.scan:
        findings += module_port_scan(cap, port_threshold=args.scan_ports,
                                     host_threshold=args.scan_hosts,
                                     top=max(args.top, 15))
    if args.beacon:
        findings += module_beaconing(cap, min_events=args.beacon_events,
                                     burst_gap=args.beacon_gap,
                                     max_interval=args.beacon_max_interval,
                                     score_threshold=args.beacon_score,
                                     top=max(args.top, 20))
    if args.dns:
        findings += module_dns_tunneling(cap, min_queries=args.dns_min_queries,
                                         entropy_threshold=args.dns_entropy,
                                         length_threshold=args.dns_length,
                                         score_threshold=args.dns_score,
                                         top=max(args.top, 15))
    if args.creds:
        findings += module_credentials(cap, reveal=args.show_secrets)
    if args.vuln:
        findings += module_vuln_scan(cap, top=max(args.top, 30))

    annotate_pyramid(findings)

    if any([args.scan, args.beacon, args.dns, args.creds, args.vuln]):
        print_executive_summary(findings, cap)

    if args.patch_plan:
        module_patch_plan(findings)

    if args.json_out:
        write_json_report(args.json_out, findings, cap, args)

    if args.export_iocs:
        n = export_iocs(findings, args.export_iocs)
        if n:
            print(f"{C.GREEN}[+] {n} distinct indicators written to "
                  f"{args.export_iocs}{C.RESET}")
        else:
            print(f"{C.DIM}[*] No IP/domain indicators in the findings to "
                  f"export.{C.RESET}")

    # Exit code: 0 clean, 1 findings present - useful for CI / automation.
    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted by user.{C.RESET}")
        sys.exit(130)

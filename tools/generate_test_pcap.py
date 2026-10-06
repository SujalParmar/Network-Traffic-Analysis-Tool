#!/usr/bin/env python3
"""
generate_test_pcap.py - Build a synthetic PCAP that triggers every detection
module in pcap_analyzer.py. Useful for demos, unit tests, and screenshots when
you don't want to depend on an external download.

    python tools/generate_test_pcap.py -o samples/synthetic_demo.pcap

Contains:
  * benign background HTTP/HTTPS/DNS noise
  * an nmap-style vertical SYN scan (1000 ports) + a horizontal 445 sweep
  * a 60s C2 beacon with 5% jitter and fixed payload size
  * base32-looking DNS tunneling over a fake domain
  * FTP, Telnet and HTTP POST cleartext credentials
"""

import argparse
import base64
import os
import random
import string

from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR

random.seed(1337)
BASE_T = 1_726_000_000.0   # fixed epoch so output is reproducible

VICTIM = "192.168.10.55"
VICTIM2 = "192.168.10.61"
ATTACKER = "192.168.10.200"
C2 = "185.243.115.84"
GATEWAY = "192.168.10.1"
DNS_SRV = "192.168.10.1"
WEB = "203.0.113.20"


def eth(src_ip, dst_ip):
    return Ether(src="00:0c:29:4f:8e:11", dst="00:50:56:c0:00:08") / IP(src=src_ip, dst=dst_ip)


def tcp_syn(src, dst, sport, dport, ts):
    p = eth(src, dst) / TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 2**32 - 1))
    p.time = ts
    return p


def tcp_data(src, dst, sport, dport, payload, ts, flags="PA"):
    p = eth(src, dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(load=payload)
    p.time = ts
    return p


def dns_query(src, qname, ts, qtype="A", sport=None):
    p = (eth(src, DNS_SRV) / UDP(sport=sport or random.randint(40000, 60000), dport=53)
         / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    p.time = ts
    return p


def build(patched=False):
    random.seed(1337)  # identical traffic on every call
    pkts = []
    t = BASE_T

    # ── 1. Benign background noise ───────────────────────────────────────
    for i in range(300):
        ts = t + i * 0.4
        sport = random.randint(49152, 65535)
        host = random.choice(["www.google.com", "cdn.cloudflare.com", "update.microsoft.com",
                              "api.github.com", "ocsp.digicert.com"])
        pkts.append(dns_query(random.choice([VICTIM, VICTIM2]), host, ts))
        pkts.append(tcp_syn(VICTIM2, WEB, sport, 443, ts + 0.02))
        pkts.append(tcp_data(VICTIM2, WEB, sport, 443,
                             os.urandom(random.randint(200, 1200)), ts + 0.05))

    # ── 2. Vertical port scan: ATTACKER -> VICTIM, 1000 ports ───────────
    t_scan = BASE_T + 130
    open_ports = {22, 80, 135, 139, 445, 3389}
    for i, port in enumerate(range(1, 1001)):
        ts = t_scan + i * 0.004
        pkts.append(tcp_syn(ATTACKER, VICTIM, 44444 + (i % 100), port, ts))
        if port in open_ports:
            r = eth(VICTIM, ATTACKER) / TCP(sport=port, dport=44444 + (i % 100), flags="SA")
            r.time = ts + 0.001
            pkts.append(r)
        elif i % 7 == 0:
            r = eth(VICTIM, ATTACKER) / TCP(sport=port, dport=44444 + (i % 100), flags="RA")
            r.time = ts + 0.001
            pkts.append(r)

    # ── 3. Horizontal SMB sweep: ATTACKER -> /24 on 445 ─────────────────
    t_sweep = BASE_T + 140
    for i in range(1, 61):
        pkts.append(tcp_syn(ATTACKER, f"192.168.10.{i}", 55555, 445, t_sweep + i * 0.05))

    # ── 4. C2 beacon: VICTIM -> C2 every 60s, 5% jitter, fixed size ─────
    t_beacon = BASE_T
    payload = b"POST /api/v2/checkin HTTP/1.1\r\nHost: cdn-telemetry.net\r\n" \
              b"User-Agent: Mozilla/5.0\r\nContent-Length: 64\r\n\r\n" + b"A" * 64
    for i in range(22):
        jitter = random.uniform(-3.0, 3.0)          # ±5% of 60s
        ts = t_beacon + i * 60 + jitter
        sport = random.randint(49152, 65535)
        pkts.append(tcp_syn(VICTIM, C2, sport, 8443, ts))
        pkts.append(tcp_data(VICTIM, C2, sport, 8443, payload, ts + 0.03))
        resp = eth(C2, VICTIM) / TCP(sport=8443, dport=sport, flags="PA") / Raw(
            load=b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nNO_TASKS")
        resp.time = ts + 0.09
        pkts.append(resp)

    # ── 5. DNS tunneling: high-entropy base32 labels ────────────────────
    alphabet = string.ascii_lowercase + string.digits
    t_dns = BASE_T + 200
    for i in range(140):
        chunk = "".join(random.choice(alphabet) for _ in range(random.randint(28, 46)))
        label = f"{chunk[:31]}.{chunk[31:]}" if len(chunk) > 31 else chunk
        qname = f"{label}.tun.exfil-node7.xyz"
        qtype = "TXT" if i % 3 == 0 else "A"
        pkts.append(dns_query(VICTIM, qname, t_dns + i * 0.35, qtype=qtype))

    # ── 6. Cleartext credentials ────────────────────────────────────────
    t_cred = BASE_T + 260
    # FTP
    pkts.append(tcp_data(VICTIM2, "203.0.113.44", 51000, 21, b"USER svc_backup\r\n", t_cred))
    pkts.append(tcp_data(VICTIM2, "203.0.113.44", 51000, 21, b"PASS Backup!2024\r\n", t_cred + 0.4))
    # HTTP POST form
    body = b"username=j.doe&password=Summer2024!&remember=1"
    http_post = (b"POST /login.php HTTP/1.1\r\nHost: intranet.corp.local\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    pkts.append(tcp_data(VICTIM, "203.0.113.20", 51002, 80, http_post, t_cred + 1.0))
    # HTTP Basic auth
    token = base64.b64encode(b"admin:P@ssw0rd123").decode()
    basic = (b"GET /admin/ HTTP/1.1\r\nHost: 203.0.113.20\r\n"
             b"Authorization: Basic " + token.encode() + b"\r\n\r\n")
    pkts.append(tcp_data(VICTIM, "203.0.113.20", 51004, 80, basic, t_cred + 1.5))
    # JSON API POST
    jbody = b'{"user":"api_svc","password":"hunter2hunter2","scope":"rw"}'
    jpost = (b"POST /api/token HTTP/1.1\r\nHost: api.corp.local\r\n"
             b"Content-Type: application/json\r\nContent-Length: "
             + str(len(jbody)).encode() + b"\r\n\r\n" + jbody)
    pkts.append(tcp_data(VICTIM, "203.0.113.21", 51006, 8080, jpost, t_cred + 2.0))
    # Telnet
    for i, line in enumerate([b"login: ", b"netadmin\r\n", b"Password: ",
                              b"Cisco123!\r\n", b"switch01> enable\r\n"]):
        pkts.append(tcp_data(VICTIM2 if i % 2 else "203.0.113.99",
                             "203.0.113.99" if i % 2 else VICTIM2,
                             51010, 23, line, t_cred + 3 + i * 0.3))
    # POP3
    pkts.append(tcp_data(VICTIM, "203.0.113.55", 51020, 110, b"USER mailuser\r\n", t_cred + 5))
    pkts.append(tcp_data(VICTIM, "203.0.113.55", 51020, 110, b"PASS Mail!pass99\r\n", t_cred + 5.3))

    # ── 7. Passive vulnerability identification test traffic ───────────
    t_vuln = BASE_T + 300
    # vsftpd 2.3.4 backdoor banner (CVE-2011-2523)
    pkts.append(tcp_data("203.0.113.77", VICTIM2, 21, 51030,
                         (b"220 (vsFTPd 3.0.5)\r\n" if patched else b"220 (vsFTPd 2.3.4)\r\n"), t_vuln, flags="PA"))
    # Apache 2.4.49 path traversal (CVE-2021-41773), banner in HTTP response
    http_resp = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix) "
                 + (b"OpenSSL/3.0.13" if patched else b"OpenSSL/1.0.1e-fips")
                 + b"\r\nContent-Length: 12\r\n\r\nHello world!")
    pkts.append(tcp_data("203.0.113.77", VICTIM2, 80, 51032,
                         http_resp, t_vuln + 0.5, flags="PA"))
    # Old OpenSSH banner (CVE-2008-5161 range)
    pkts.append(tcp_data("203.0.113.88", VICTIM2, 22, 51034,
                         (b"SSH-2.0-OpenSSH_9.6p1\r\n" if patched else b"SSH-2.0-OpenSSH_5.1\r\n"), t_vuln + 1.0, flags="PA"))
    # Deprecated TLS 1.0 ClientHello (minimal, just enough to be parsed:
    # record type 0x16, version 0x0301, handshake type 0x01)
    tls_minor = 0x03 if patched else 0x01   # TLS 1.2 after the fix, TLS 1.0 before
    tls10_hello = bytes([0x16, 0x03, tls_minor, 0x00, 0x2f, 0x01, 0x00, 0x00,
                         0x2b, 0x03, tls_minor]) + os.urandom(40)
    pkts.append(tcp_data(VICTIM, "203.0.113.90", 51036, 443,
                         tls10_hello, t_vuln + 1.5, flags="PA"))

    pkts.sort(key=lambda p: p.time)
    return pkts


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate a synthetic test PCAP.")
    ap.add_argument("-o", "--out", default="samples/synthetic_demo.pcap")
    ap.add_argument("--patched", action="store_true",
                    help="build the after-patching variant: vsftpd, OpenSSH, "
                         "OpenSSL and the TLS version upgraded, Apache 2.4.49 "
                         "left unpatched on purpose")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    packets = build(patched=a.patched)
    wrpcap(a.out, packets)
    print(f"[+] Wrote {len(packets):,} packets to {a.out} "
          f"({os.path.getsize(a.out) / 1024:.1f} KB)")

#!/usr/bin/env python3
"""
Unit tests for pcap_analyzer detection modules.

    python -m unittest discover -s tests -v
    # or, if you have pytest:  pytest -q

Builds a synthetic capture once, then asserts that each module produces the
expected findings. Keeps stdout quiet so test output stays readable.
"""

import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pcap_analyzer as pa  # noqa: E402
from tools.generate_test_pcap import build  # noqa: E402
from scapy.all import wrpcap  # noqa: E402

PCAP = "/tmp/_pa_test.pcap"


def quiet(fn, *a, **kw):
    """Run a module and swallow its table output."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return fn(*a, **kw)


def setUpModule():
    """Built once at module scope - unittest runs CLITests before
    DetectionTests alphabetically, so the fixture cannot live in setUpClass."""
    wrpcap(PCAP, build())


class DetectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cap = quiet(pa.Capture(PCAP).load)

    # ---------- ingestion ----------
    def test_capture_loads(self):
        self.assertGreater(self.cap.total_packets, 1000)
        self.assertEqual(self.cap.malformed, 0)
        self.assertGreater(self.cap.duration, 0)

    def test_protocols_counted(self):
        self.assertIn("TCP", self.cap.proto_counter)
        self.assertIn("DNS", self.cap.proto_counter)

    # ---------- helpers ----------
    def test_entropy_bounds(self):
        self.assertEqual(pa.shannon_entropy(""), 0.0)
        self.assertEqual(pa.shannon_entropy("aaaaaa"), 0.0)
        self.assertAlmostEqual(pa.shannon_entropy("abcd"), 2.0, places=6)
        self.assertGreater(pa.shannon_entropy("k7bp1owf2fp0760ab8waxoa4se5lg6"), 3.5)

    def test_registered_domain_split(self):
        self.assertEqual(pa.registered_domain("a.b.example.com"),
                         ("a.b", "example.com"))
        self.assertEqual(pa.registered_domain("example.com"), ("", "example.com"))
        self.assertEqual(pa.registered_domain("x.y.foo.co.uk"), ("x.y", "foo.co.uk"))

    def test_masking(self):
        masked = pa.mask("Summer2024!", reveal=False)
        self.assertTrue(masked.startswith("Su"))
        self.assertNotIn("2024", masked)        # body is hidden
        self.assertLessEqual(len(masked), 12)   # asterisk run is capped
        self.assertEqual(pa.mask("Summer2024!", reveal=True), "Summer2024!")
        self.assertEqual(pa.mask("ab", reveal=False), "ab")  # too short to mask

    def test_event_collapsing(self):
        # three bursts of two packets each, 10s apart
        ts = [0, 0.1, 10, 10.1, 20, 20.1]
        self.assertEqual(len(pa._collapse_to_events(ts, gap=2.0)), 3)

    # ---------- detection modules ----------
    def test_port_scan_detected(self):
        f = quiet(pa.module_port_scan, self.cap)
        vertical = [x for x in f if "Vertical" in x.title]
        horizontal = [x for x in f if "Horizontal" in x.title]
        self.assertTrue(vertical, "vertical scan not detected")
        self.assertTrue(horizontal, "horizontal sweep not detected")
        self.assertEqual(vertical[0].src, "192.168.10.200")
        self.assertGreaterEqual(vertical[0].evidence["distinct_ports"], 900)
        self.assertIn(445, vertical[0].evidence["open_ports"])

    def test_no_false_positive_scan_on_benign_host(self):
        f = quiet(pa.module_port_scan, self.cap)
        self.assertNotIn("192.168.10.61", [x.src for x in f])

    def test_beaconing_detected(self):
        f = quiet(pa.module_beaconing, self.cap)
        self.assertTrue(f, "beacon not detected")
        b = f[0]
        self.assertEqual(b.dst, "185.243.115.84:8443")
        self.assertAlmostEqual(b.evidence["median_interval_sec"], 60, delta=4)
        self.assertLess(b.evidence["jitter_pct"], 15)
        self.assertIn(b.severity, ("HIGH", "CRITICAL"))

    def test_beacon_threshold_respected(self):
        f = quiet(pa.module_beaconing, self.cap, score_threshold=99.9,
                  min_events=500)
        self.assertEqual(f, [])

    def test_dns_tunneling_detected(self):
        f = quiet(pa.module_dns_tunneling, self.cap)
        self.assertTrue(f, "DNS tunneling not detected")
        d = f[0]
        self.assertEqual(d.dst, "exfil-node7.xyz")
        self.assertGreater(d.evidence["avg_entropy_bits_per_char"], 3.5)
        self.assertGreater(d.evidence["unique_ratio"], 0.9)

    def test_benign_domains_not_flagged(self):
        f = quiet(pa.module_dns_tunneling, self.cap)
        flagged = {x.dst for x in f}
        for good in ("google.com", "cloudflare.com", "microsoft.com", "github.com"):
            self.assertNotIn(good, flagged)

    # ---------- vulnerability identification ----------
    def test_vuln_scan_detects_known_signatures(self):
        f = quiet(pa.module_vuln_scan, self.cap)
        cves = {x.evidence["cve"] for x in f}
        self.assertIn("CVE-2011-2523", cves)   # vsftpd 2.3.4 backdoor
        self.assertIn("CVE-2021-41773", cves)  # Apache 2.4.49 path traversal
        self.assertIn("CVE-2014-0160", cves)   # Heartbleed via OpenSSL banner
        self.assertIn("CVE-2008-5161", cves)   # outdated OpenSSH

    def test_vuln_scan_detects_deprecated_tls(self):
        f = quiet(pa.module_vuln_scan, self.cap)
        tls_findings = [x for x in f if "TLS 1.0" in x.title]
        self.assertTrue(tls_findings, "deprecated TLS 1.0 not flagged")
        self.assertEqual(tls_findings[0].severity, "MEDIUM")

    def test_vuln_scan_no_duplicate_findings(self):
        f = quiet(pa.module_vuln_scan, self.cap)
        keys = [(x.src, x.dst, x.evidence["cve"]) for x in f]
        self.assertEqual(len(keys), len(set(keys)), "duplicate finding emitted")

    def test_vuln_scan_case_insensitive_banner_match(self):
        # Real vsftpd banners render as "vsFTPd" (mixed case); confirm the
        # signature still matches regardless of case.
        f = quiet(pa.module_vuln_scan, self.cap)
        self.assertTrue(any(x.evidence["cve"] == "CVE-2011-2523" for x in f))

    def test_vuln_scan_carries_cvss_and_remediation(self):
        f = quiet(pa.module_vuln_scan, self.cap)
        vsftpd = next(x for x in f if x.evidence["cve"] == "CVE-2011-2523")
        self.assertEqual(vsftpd.evidence["cvss"], 9.8)
        self.assertIn("vsftpd 3", vsftpd.evidence["remediation"])
        self.assertIn("CVSS 9.8", vsftpd.title)
        # every vuln finding must carry both fields, not just the ones we spot-check
        for x in f:
            self.assertIsInstance(x.evidence["cvss"], float)
            self.assertTrue(x.evidence["remediation"])

    # ---------- pyramid of pain tagging ----------
    def test_pyramid_tags_applied_correctly(self):
        findings = (quiet(pa.module_port_scan, self.cap)
                   + quiet(pa.module_beaconing, self.cap)
                   + quiet(pa.module_dns_tunneling, self.cap)
                   + quiet(pa.module_vuln_scan, self.cap))
        pa.annotate_pyramid(findings)
        by_module = {f.module: f for f in findings}
        self.assertEqual(by_module["port_scan"].pyramid_tier, 2)
        self.assertEqual(by_module["beaconing"].pyramid_tier, 6)
        self.assertEqual(by_module["dns_tunneling"].pyramid_tier, 3)
        self.assertEqual(by_module["vuln_scan"].pyramid_tier, 4)
        self.assertIn("TTPs", by_module["beaconing"].pyramid)
        self.assertTrue(by_module["port_scan"].evidence["pyramid_reason"])

    def test_pyramid_unclassified_module_is_safe(self):
        f = pa.Finding(module="made_up_module", severity="LOW", title="x")
        pa.annotate_pyramid([f])
        self.assertEqual(f.pyramid_tier, 0)
        self.assertEqual(f.pyramid, "Unclassified")

    # ---------- IOC export ----------
    def test_export_iocs_writes_expected_indicators(self):
        findings = (quiet(pa.module_port_scan, self.cap)
                   + quiet(pa.module_dns_tunneling, self.cap))
        pa.annotate_pyramid(findings)
        out_path = "/tmp/_pa_test_iocs.csv"
        n = pa.export_iocs(findings, out_path)
        self.assertGreater(n, 0)
        with open(out_path) as fh:
            content = fh.read()
        self.assertIn("192.168.10.200", content)   # scanner IP
        self.assertIn("exfil-node7.xyz", content)   # tunneling domain
        self.assertIn("ip", content)
        self.assertIn("domain", content)
        os.remove(out_path)

    def test_export_iocs_empty_when_no_indicators(self):
        f = pa.Finding(module="summary_only", severity="LOW", title="x",
                       src="", dst="")
        n = pa.export_iocs([f], "/tmp/_pa_test_iocs_empty.csv")
        self.assertEqual(n, 0)
        self.assertFalse(os.path.exists("/tmp/_pa_test_iocs_empty.csv"))

    def test_export_iocs_dedupes_and_keeps_worst_severity(self):
        f1 = pa.Finding(module="port_scan", severity="MEDIUM", title="a",
                        src="10.0.0.5", dst="10.0.0.9")
        f2 = pa.Finding(module="port_scan", severity="CRITICAL", title="b",
                        src="10.0.0.5", dst="10.0.0.9")
        pa.annotate_pyramid([f1, f2])
        out_path = "/tmp/_pa_test_iocs_dedupe.csv"
        n = pa.export_iocs([f1, f2], out_path)
        with open(out_path) as fh:
            content = fh.read()
        # 10.0.0.5 appears once, kept at its worst (CRITICAL) severity
        self.assertEqual(content.count("10.0.0.5"), 1)
        self.assertIn("CRITICAL", content)
        os.remove(out_path)

    def test_credentials_detected(self):
        f = quiet(pa.module_credentials, self.cap)
        protos = {x.evidence["protocol"] for x in f}
        for expected in ("FTP", "HTTP", "TELNET", "POP3"):
            self.assertIn(expected, protos, f"{expected} creds missed")

    def test_credential_values_recovered(self):
        f = quiet(pa.module_credentials, self.cap, reveal=True)
        secrets = {x.evidence["secret"] for x in f}
        users = {x.evidence["username"] for x in f}
        self.assertIn("Summer2024!", secrets)      # HTTP POST form
        self.assertIn("P@ssw0rd123", secrets)      # HTTP Basic auth
        self.assertIn("Backup!2024", secrets)      # FTP
        self.assertIn("Cisco123!", secrets)        # Telnet transcript
        self.assertIn("j.doe", users)
        self.assertIn("netadmin", users)

    def test_secrets_masked_by_default(self):
        f = quiet(pa.module_credentials, self.cap, reveal=False)
        for x in f:
            self.assertNotIn("Summer2024!", x.evidence["secret"])

    # ---------- reporting ----------
    def test_findings_serialise_to_json(self):
        import json
        f = quiet(pa.module_port_scan, self.cap)
        json.dumps([x.to_dict() for x in f], default=str)  # must not raise

    def test_severity_ordering(self):
        f = (quiet(pa.module_port_scan, self.cap)
             + quiet(pa.module_credentials, self.cap))
        ordered = sorted(f, key=lambda x: pa.SEVERITY_ORDER[x.severity])
        self.assertEqual(ordered[0].severity, "CRITICAL")


class CLITests(unittest.TestCase):
    def test_cli_runs_all_modules(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pa.main(["-r", PCAP, "--all", "--no-color", "-q"])
        out = buf.getvalue()
        self.assertEqual(rc, 1)               # 1 = high/critical findings present
        for section in ("TRAFFIC SUMMARY", "PORT SCAN DETECTION",
                        "C2 BEACONING DETECTION", "DNS TUNNELING",
                        "CLEARTEXT CREDENTIAL", "PASSIVE VULNERABILITY",
                        "EXECUTIVE SUMMARY"):
            self.assertIn(section, out)

    def test_cli_writes_json(self):
        import json
        out_path = "/tmp/_pa_test_report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            pa.main(["-r", PCAP, "--all", "--no-color", "-q", "--json", out_path])
        with open(out_path) as fh:
            report = json.load(fh)
        self.assertIn("findings", report)
        self.assertGreater(len(report["findings"]), 5)
        self.assertGreater(report["capture"]["packets"], 1000)
        self.assertIn("protocol_counts", report["capture"])
        os.remove(out_path)

    def test_cli_exports_iocs(self):
        out_path = "/tmp/_pa_test_iocs_cli.csv"
        with contextlib.redirect_stdout(io.StringIO()):
            pa.main(["-r", PCAP, "--all", "--no-color", "-q",
                    "--export-iocs", out_path])
        self.assertTrue(os.path.exists(out_path))
        with open(out_path) as fh:
            content = fh.read()
        self.assertIn("indicator,type,severity,module,pyramid_level", content)
        os.remove(out_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

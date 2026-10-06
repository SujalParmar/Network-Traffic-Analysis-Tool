#!/usr/bin/env python3
"""
Tests for the patch planning (--patch-plan) and remediation check (--compare)
features. They use the synthetic capture before and after patching.

    python -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pcap_analyzer as pa  # noqa: E402
from tools.generate_test_pcap import build  # noqa: E402
from scapy.all import wrpcap  # noqa: E402

BEFORE = "/tmp/_pa_patch_before.pcap"
AFTER = "/tmp/_pa_patch_after.pcap"


def quiet(fn, *a, **kw):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


def vuln_findings(path):
    cap = quiet(pa.Capture(path).load)
    return quiet(pa.module_vuln_scan, cap)


def write_report(path, findings):
    with open(path, "w") as fh:
        json.dump({"findings": [f.to_dict() for f in findings]}, fh)


def setUpModule():
    wrpcap(BEFORE, build())
    wrpcap(AFTER, build(patched=True))


class PatchPlanTests(unittest.TestCase):

    def test_patch_target_bands(self):
        self.assertEqual(pa.patch_target(9.8), ("P1", "within 72 hours"))
        self.assertEqual(pa.patch_target(9.0)[0], "P1")
        self.assertEqual(pa.patch_target(7.5), ("P2", "within 7 days"))
        self.assertEqual(pa.patch_target(7.0)[0], "P2")
        self.assertEqual(pa.patch_target(5.9), ("P3", "within 30 days"))
        self.assertEqual(pa.patch_target(4.0)[0], "P3")
        self.assertEqual(pa.patch_target(3.9)[0], "P4")
        self.assertEqual(pa.patch_target(0.0)[0], "P4")

    def test_plan_only_contains_vulnerabilities_worst_first(self):
        other = pa.Finding(module="port_scan", severity="HIGH", title="scan")
        plan = pa.build_patch_plan(vuln_findings(BEFORE) + [other])
        self.assertEqual(len(plan), 5)
        scores = [r["cvss"] for r in plan]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(plan[0]["priority"], "P1")
        self.assertEqual(plan[-1]["priority"], "P3")

    def test_every_plan_entry_has_a_fix_and_a_window(self):
        for r in pa.build_patch_plan(vuln_findings(BEFORE)):
            self.assertTrue(r["fix"])
            self.assertTrue(r["window"])

    def test_cli_patch_plan_prints_the_plan(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pa.main(["-r", BEFORE, "--patch-plan", "--no-color", "-q"])
        out = buf.getvalue()
        self.assertIn("PATCH PLAN", out)
        self.assertIn("P1", out)
        self.assertIn("CVE-2011-2523", out)


class RemediationCheckTests(unittest.TestCase):

    def test_patched_capture_resolves_most_and_keeps_apache(self):
        before, after = vuln_findings(BEFORE), vuln_findings(AFTER)
        write_report("/tmp/_pa_b.json", before)
        write_report("/tmp/_pa_a.json", after)
        r = pa.compare_reports("/tmp/_pa_b.json", "/tmp/_pa_a.json")
        resolved = {f["evidence"]["cve"] for f in r["resolved"]}
        remaining = {f["evidence"]["cve"] for f in r["remaining"]}
        self.assertEqual(resolved, {"CVE-2011-2523", "CVE-2014-0160",
                                    "CVE-2008-5161", "weak-tls-1"})
        self.assertEqual(remaining, {"CVE-2021-41773"})
        self.assertEqual(r["new"], [])

    def test_reversed_comparison_shows_new_findings(self):
        write_report("/tmp/_pa_b.json", vuln_findings(AFTER))
        write_report("/tmp/_pa_a.json", vuln_findings(BEFORE))
        r = pa.compare_reports("/tmp/_pa_b.json", "/tmp/_pa_a.json")
        self.assertEqual(len(r["new"]), 4)
        self.assertEqual(len(r["remaining"]), 1)
        self.assertEqual(r["resolved"], [])

    def test_cli_compare_needs_no_pcap_and_signals_what_remains(self):
        write_report("/tmp/_pa_b.json", vuln_findings(BEFORE))
        write_report("/tmp/_pa_a.json", vuln_findings(AFTER))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pa.main(["--compare", "/tmp/_pa_b.json", "/tmp/_pa_a.json",
                          "--no-color"])
        self.assertEqual(rc, 1)  # Apache is still unpatched
        out = buf.getvalue()
        self.assertIn("REMEDIATION CHECK", out)
        self.assertIn("Still present", out)

    def test_clean_comparison_returns_zero(self):
        write_report("/tmp/_pa_b.json", vuln_findings(AFTER))
        write_report("/tmp/_pa_a.json", [])
        with contextlib.redirect_stdout(io.StringIO()):
            rc = pa.main(["--compare", "/tmp/_pa_b.json", "/tmp/_pa_a.json",
                          "--no-color"])
        self.assertEqual(rc, 0)

    def test_unreadable_report_exits_with_a_message(self):
        with self.assertRaises(SystemExit):
            pa.compare_reports("/tmp/does_not_exist.json", "/tmp/_pa_a.json")

    def test_pcap_is_required_without_compare(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                pa.main(["--scan"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

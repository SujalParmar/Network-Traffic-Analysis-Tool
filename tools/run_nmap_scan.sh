#!/usr/bin/env bash
#
# run_nmap_scan.sh - active vulnerability scan companion for pcap_analyzer.py
#
# pcap_analyzer.py's --vuln module is PASSIVE: it only reads what services
# already announced in a capture, so it can only find what happened to be
# running and talking during the recording window. This script runs a real
# ACTIVE scan with Nmap's vulnerability-scripting engine against a host you
# own or have explicit permission to test - typically a lab VM from the
# Active Directory / SOC lab project - and saves the output into reports/
# so the two results can be compared side by side in a writeup:
# "the passive PCAP analysis found X; an active Nmap scan of the same host
# confirmed/expanded on it with Y."
#
# USAGE:
#   ./tools/run_nmap_scan.sh <target-ip-or-host>
#   (if you get 'Permission denied': chmod +x tools/run_nmap_scan.sh,
#    or run it as: bash tools/run_nmap_scan.sh <target>)
#
# Example:
#   ./tools/run_nmap_scan.sh 192.168.56.10
#
# REQUIRES: nmap (pre-installed on Kali; `sudo apt install nmap` elsewhere)
#
# ⚠️  LEGAL / SAFETY: only ever point this at a host you own or have
#     explicit written permission to scan - your own lab VM, not anyone
#     else's machine or network. Unauthorised scanning is illegal in most
#     jurisdictions even when no exploit is actually run.
#
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <target-ip-or-hostname>"
  echo "Example: $0 192.168.56.10   (your lab VM's IP)"
  exit 1
fi

TARGET="$1"
OUT_DIR="$(dirname "$0")/../reports"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_BASE="$OUT_DIR/nmap_vuln_scan_${STAMP}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "[!] nmap is not installed."
  echo "    Kali: it should already be present - try 'sudo apt update && sudo apt install nmap'"
  echo "    Other Linux: sudo apt install nmap   (or your distro's package manager)"
  exit 1
fi

echo "[*] Target: $TARGET"
echo "[*] Make sure this is a host you own or have explicit permission to scan."
read -r -p "    Continue? [y/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
  echo "[*] Aborted."
  exit 0
fi

echo "[*] Running service/version detection + vuln scripts (this can take a few minutes)..."
# -sV        : detect service/version (feeds the vuln scripts)
# --script vuln : run every NSE script in the 'vuln' category
# -oN        : save human-readable output alongside the raw XML
nmap -sV --script vuln -oN "${OUT_BASE}.txt" -oX "${OUT_BASE}.xml" "$TARGET"

echo
echo "[+] Scan complete."
echo "[+] Human-readable report: ${OUT_BASE}.txt"
echo "[+] Raw XML (for tooling):  ${OUT_BASE}.xml"
echo
echo "Next step: compare these findings against what pcap_analyzer.py --vuln"
echo "found from a packet capture of the same host, and note in your README"
echo "or writeup where the active scan found things the passive one missed"
echo "(and vice versa - passive analysis can catch things that only appear"
echo "in live traffic, like an actual credential being sent)."

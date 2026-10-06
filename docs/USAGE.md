# Usage reference

[Back to README](../README.md) | [Documentation index](README.md)

## Commands

```bash
# Full analysis
python pcap_analyzer.py -r capture.pcap --all

# Single modules
python pcap_analyzer.py -r capture.pcap --summary
python pcap_analyzer.py -r capture.pcap --scan --beacon
python pcap_analyzer.py -r capture.pcap --vuln

# Export findings and IOCs
python pcap_analyzer.py -r capture.pcap --all --json reports/findings.json
python pcap_analyzer.py -r capture.pcap --all --export-iocs reports/iocs.csv

# Patch plan and remediation check
python pcap_analyzer.py -r capture.pcap --patch-plan
python pcap_analyzer.py --compare reports/before.json reports/after.json

# Loosen DNS thresholds when hunting a quiet tunnel
python pcap_analyzer.py -r capture.pcap --dns --dns-entropy 3.0 --dns-score 45

# Reveal recovered passwords (masked by default)
python pcap_analyzer.py -r capture.pcap --creds --show-secrets

# Focus on one suspect host, or cap work on a very large capture
python pcap_analyzer.py -r capture.pcap --all --filter-src 10.0.0.55
python pcap_analyzer.py -r huge.pcap --all --max-packets 500000
```

## IOC export

The IOC export pulls every distinct IP and domain out of the findings, keeps each at its worst severity, tags it with its Pyramid of Pain level and writes a flat CSV:

```csv
indicator,type,severity,module,pyramid_level,example_finding
185.243.115.84,ip,CRITICAL,beaconing,TTPs (tier 6/6),Periodic callback every ~60s...
exfil-node7.xyz,domain,CRITICAL,dns_tunneling,Domain Names (tier 3/6),Probable DNS tunneling...
```

## Tuning flags

| Flag | Default | Meaning |
|---|---|---|
| `--scan-ports N` | 15 | Distinct ports on one target before flagging a vertical scan |
| `--scan-hosts N` | 15 | Distinct hosts on one port before flagging a sweep |
| `--beacon-events N` | 6 | Minimum callbacks needed before a flow is scored |
| `--beacon-gap SEC` | 2.0 | Packets closer than this collapse into a single session event |
| `--beacon-score N` | 65 | Regularity score (0-100) required to report |
| `--dns-entropy BITS` | 3.3 | Average Shannon entropy per character to flag |
| `--dns-length N` | 25 | Average subdomain length to flag |
| `--dns-score N` | 55 | Composite DNS score required to report |
| `--top N` | 10 | Rows shown in ranked tables |

Lower the thresholds to increase sensitivity at the cost of false positives. Every finding in the JSON output carries the raw metrics that produced it, so thresholds can be re-tuned against a known-good baseline capture.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Ran successfully, no high or critical findings |
| 1 | High or critical findings present (or, with `--compare`, findings remain or are new) |
| 2 | Capture contained no readable packets |
| 130 | Interrupted |

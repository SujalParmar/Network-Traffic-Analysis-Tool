# Nessus scan summary

Active vulnerability scan of my Kali Linux lab host with Nessus Essentials, run
as a companion to the passive analysis done by `pcap_analyzer.py --vuln`.

## Scan details

| Item | Value |
|---|---|
| Date | 2026-10-05 |
| Scanner | Tenable Nessus Essentials (Nessus 19.18.5) |
| Scan template | Basic Network Scan |
| Scan name | Kali-baseline |
| Target | 192.168.10.250 (my own Kali Linux VM, private lab address) |
| Duration | 9 minutes |
| Severity base | CVSS v3.0 |
| Service exposed for the scan | OpenSSH (started on purpose so there was a service to assess) |

Only a machine I own was scanned.

## Results

Nessus reported 92 findings for the host.

| Severity | Result |
|---|---|
| Critical | none |
| High | none |
| Medium | 1 |
| Low | none |
| Info | the remaining findings |

Info results are not vulnerabilities. They are details Nessus reports about the
host, such as the operating system, open ports and detected services.

![Scan summary](nessus_scan_summary_screen.png)

### The Medium finding

| Field | Value |
|---|---|
| Name | SSL Certificate Cannot Be Trusted (plugin 51192) |
| CVSS v3.0 base score | 6.5 |
| Port | 8834/tcp (www) |
| Certificate subject | CN=kali, O=Nessus Users United, OU=Nessus Server |
| Certificate issuer | Nessus Certification Authority |
| Solution given by Nessus | Purchase or generate a proper SSL certificate for this service |

![Finding description](nessus_medium_finding_top.png)

![Finding solution and output](nessus_medium_finding_bottom.png)

## Interpretation

Port 8834 is Nessus's own web interface, and the certificate in question is the
self-signed one Nessus generates for itself when it is installed. The finding
therefore concerns the scanner's own management page, not the operating system
or any of the host's other services. It appears on any default Nessus install.

## Remediation

The fix is to install a certificate from a trusted authority on the Nessus
interface. That is a certificate management task, not a software update.

## Limitations

- Nessus Essentials cannot export PDF or HTML reports, so the evidence is
  screenshots of the results screens.
- The target is a single, up-to-date lab host, so a clean result says little
  about a typical production machine.
- The license shown in the Nessus interface was time-limited (about 30 days from
  activation).

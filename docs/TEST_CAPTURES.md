# Test captures

[Back to README](../README.md) | [Documentation index](README.md)

The tool is designed for real traffic as well as the synthetic capture. Good sources:

**Malware Traffic Analysis** - <https://www.malware-traffic-analysis.net/training-exercises.html>
Brad Duncan's archive of real infection captures, organised as training exercises with answer keys. Best source for beaconing and HTTP C2 traffic. Captures are distributed as password-protected ZIPs; the password is published on the site (`infected`) to stop accidental execution of the malware samples bundled alongside.

**Wireshark sample captures** - <https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures>
Small single-protocol captures. `telnet-cooked.pcap`, the FTP captures and `iseries.cap` are useful for exercising the credential module.

**Netresec public PCAP index** - <https://www.netresec.com/?page=PcapFiles>
A curated index of most other public capture repositories, including the MACCDC and ISTS defence-competition captures, which contain heavy scanning activity.

**Stratosphere IPS malware captures** - <https://www.stratosphereips.org/datasets-overview>
Long-duration botnet captures from the Czech Technical University, useful for testing beaconing detection because they run for hours.

## Working safely with malware captures

Analyse them in a VM, keep the network adapter disabled, and never let a tool resolve or connect to the domains inside a capture. This tool is fully offline and performs no DNS lookups and opens no sockets, but verify that for any tool you point at hostile traffic. Captures are gitignored so the repository stays small and no real traffic is ever published.

# Testing and performance

[Back to README](../README.md) | [Documentation index](README.md)

## Testing

```bash
python -m unittest discover -s tests -v
```

40 tests cover packet ingestion, the entropy and domain-parsing helpers, each detection module against the synthetic capture with known ground truth, false-positive checks on benign hosts and domains, threshold behaviour, JSON and IOC export, the patch plan, the remediation check, and the command line end to end.

| File | Tests | Covers |
|---|---|---|
| `tests/test_detections.py` | 30 | Ingestion, helpers, the six modules, Pyramid tagging, IOC export, CLI |
| `tests/test_patch_tools.py` | 10 | Priority bands, plan ordering, before and after comparison, exit codes, error handling |

During development the parser was also crash-tested against 38 public protocol captures (VLAN, GRE, IPsec, PPPoE and other encapsulations) from the `kaorimatz/pcaps` repository, with no parse failures. These are protocol samples, not malware captures. Malformed packets are counted and skipped instead of aborting a run.

To check that the tests catch real regressions, the case-insensitivity fix was removed from a copy of the tool on purpose. The suite then failed with `failures=2, errors=1`, all in the vulnerability tests, and passed again once the file was restored (see Phase 9 in the README).

## Performance

Roughly 5,000 packets per second, dominated by Scapy's dissection rather than the detection logic. A 100,000-packet capture takes about 20 seconds and peaks near 150 MB of RSS. Captures are streamed with `PcapReader` rather than loaded whole, and only a flattened record per packet is retained. For very large files use `--max-packets` or pre-filter with `tcpdump` or `editcap`.

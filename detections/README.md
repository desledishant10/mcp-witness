# detections

Defender signatures for the vulnerability classes mcp-witness found and
disclosed, plus a self-contained validator that proves each rule fires on the
attack it is meant to catch and stays quiet on benign traffic.

The scanner and the PoC harnesses are the offensive half of this repo: they
show how MCP servers break. This module is the other half. The fastest way to
write a good detection is to first understand exactly how the thing breaks, and
every rule here is anchored to a finding that was proven end to end, not to a
hypothesis. Each one ships with the fixtures that demonstrate it and a check
that runs on every commit.

## What it detects

| Finding class (proven in this repo) | Rule | Data source | Signature |
|---|---|---|---|
| SSRF to cloud metadata (credential theft) | `mcp_ssrf_imds_credential_egress` | egress / proxy logs | request to `169.254.169.254` or a cloud credential-metadata path |
| SSRF to internal services | `mcp_ssrf_reserved_ip_egress` | egress / proxy logs | MCP fetch tool reaching an RFC1918 / loopback / link-local IP |
| DNS rebinding (delivery vector) | `mcp_dns_rebind_answer` | resolver / passive DNS | public name answered with a private IP at low TTL |
| DNS rebinding / cross-origin drive (server-side) | `mcp_dns_rebind_origin_host_mismatch` | MCP HTTP access logs | inbound request to a local MCP port with a non-local `Origin` or `Host` |

The two SSRF rules map to the [`mcp-server-fetch` SSRF writeup](https://desledishant10.github.io/mcp-witness/docs/ssrf-mcp-server-fetch);
the two rebind rules map to the [DNS-rebinding class writeup](https://desledishant10.github.io/mcp-witness/docs/dns-rebinding-http-mcp-servers).
Each rule carries CWE and MITRE ATT&CK tags in its metadata.

## Layout

```
sigma/            portable Sigma rules (one file per detection)
suricata/         network signatures for the same classes (SIDs 9000001+)
fixtures/         event fixtures modeled on real PoC output (attack + benign)
validation.yml    ground truth: which rules must fire on which events
sigma_lite.py     dependency-free evaluator for the Sigma subset used here
suricata_lint.py  structural linter for the Suricata rules
adapters.py       parse live PoC output into normalized events
validate.py       `mcp-witness-detect`: offline validation + suricata lint
validate_live.py  run the real PoC probes and match their output
```

## Validate

```bash
make validate           # rules vs. fixtures vs. ground truth, plus a suricata lint
make test               # the pytest suite for this module
make validate-live      # run the real PoC probes and match their actual output
make validate-suricata  # load the rules in Suricata itself (needs the binary)
```

`make validate` (also `mcp-witness-detect`) runs every Sigma rule against every
fixture and checks the result against `validation.yml`: an attack event must
fire exactly its expected rules and a benign event must fire nothing, so a
single miss or a single false positive fails the build. This runs offline with
no Sigma toolchain and no SIEM, using the small evaluator in `sigma_lite.py`.

`make validate-live` closes the loop against real attacks. The SSRF leg is fully
self-contained (a stdlib IMDS mock, no Docker, no install) and runs anywhere;
the DNS-rebind leg pip-installs and launches the real vulnerable server, so it
needs network access and is skipped, not failed, when it cannot run.

## Deploy

The Sigma rules are standard and convert to a SIEM backend with pySigma /
`sigma-cli`, for example:

```bash
sigma convert -t splunk -p sysmon detections/sigma/mcp_ssrf_imds_credential_egress.yml
```

The Suricata rules drop into a sensor rule file; tune `$HOME_NET` and define
`$MCP_PORTS` for the HTTP-transport ports you run. Validate structure without
the engine via `make lint-suricata`, or load them in Suricata with
`make validate-suricata`.

## Honesty carries over from the findings

The same caveat from the DNS-rebinding writeup applies to the detections. The
server-side rule (`mcp_dns_rebind_origin_host_mismatch`) fires on the missing
check itself, which is directly observable and not in dispute. The DNS-answer
rule (`mcp_dns_rebind_answer`) covers the delivery vector, where landing a live
browser rebind is the non-trivial step. The two are separate signatures on
purpose, the same way the writeup keeps the flaw and the delivery separate.

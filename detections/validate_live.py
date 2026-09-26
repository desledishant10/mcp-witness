"""Run the actual PoC quick probes and validate the detections against their
real output, closing the offense->detection loop end to end.

The SSRF probe (poc/ssrf/quick_probe.py) is fully self-contained: a stdlib IMDS
mock, no Docker and no package install, so this leg runs anywhere. The
DNS-rebind probe (poc/dns-rebind/quick_probe.py) pip-installs and launches the
real vulnerable server, so it needs network access; if it cannot run, that leg
is skipped with a message rather than failing the run.

    python -m detections.validate_live
    make validate-live
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from detections import adapters
from detections.sigma_lite import load_rules

_PKG = Path(__file__).resolve().parent
_ROOT = _PKG.parent


def _rules_by_stem():
    return {r.path.stem: r for r in load_rules(_PKG / "sigma")}


def _run(cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "quick_probe.py"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_ssrf(rules) -> bool:
    proc = _run(_ROOT / "poc" / "ssrf", timeout=90)
    events = adapters.parse_ssrf_probe(proc.stdout)
    rule = rules["mcp_ssrf_imds_credential_egress"]
    fired = [e for e in events if rule.matches(e)]
    print(
        f"[ssrf]       probe emitted {len(events)} egress event(s); IMDS rule fired on {len(fired)}"
    )
    return bool(events) and len(fired) == len(events)


def run_dns(rules) -> bool | None:
    try:
        proc = _run(_ROOT / "poc" / "dns-rebind", timeout=240)
    except Exception as exc:  # noqa: BLE001 - any failure here is a skip, not a fail
        print(f"[dns-rebind] skipped (could not run probe: {exc})")
        return None
    events = adapters.parse_dns_rebind_probe(proc.stdout)
    if not events:
        print("[dns-rebind] skipped (no hostile-probe output parsed; needs network + install)")
        return None
    rule = rules["mcp_dns_rebind_origin_host_mismatch"]
    fired = [e for e in events if rule.matches(e)]
    print(
        f"[dns-rebind] probe emitted {len(events)} inbound event(s); rebind rule fired on {len(fired)}"
    )
    return len(fired) == len(events)


def main(argv: list[str] | None = None) -> int:
    rules = _rules_by_stem()
    ssrf_ok = run_ssrf(rules)
    dns_ok = run_dns(rules)  # True / False / None(skipped)
    overall = ssrf_ok and dns_ok is not False
    print("\nLIVE VALIDATION:", "PASS" if overall else "FAIL")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())

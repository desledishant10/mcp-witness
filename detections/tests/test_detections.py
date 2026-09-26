"""Tests for the mcp-witness detections module.

The headline test is ``test_all_rules_validate``: it proves every Sigma rule
fires on exactly the attacks it should and stays silent on benign traffic. The
rest exercise the Sigma-lite engine, the Suricata linter, and the live-output
adapters.
"""

from __future__ import annotations

from detections import adapters, suricata_lint
from detections.sigma_lite import Rule, load_rules
from detections.validate import (
    SIGMA_DIR,
    SURICATA_RULES,
    run_sigma_validation,
)


# --------------------------------------------------------------------------- #
# The end-to-end validation: rules vs. fixtures vs. ground truth
# --------------------------------------------------------------------------- #
def test_all_rules_validate():
    rows, ok = run_sigma_validation()
    failures = [r for r in rows if r["status"] != "PASS"]
    assert ok, f"detection validation failed: {failures}"
    # Sanity: we actually exercised attack and benign fixtures.
    assert any(r["fired"] for r in rows)
    assert any(not r["fired"] for r in rows)


def test_every_rule_fires_on_something():
    """No dead rules: each shipped rule matches at least one fixture."""
    rows, _ = run_sigma_validation()
    fired_rules = {stem for r in rows for stem in r["fired"]}
    shipped = {p.stem for p in SIGMA_DIR.glob("*.yml")}
    assert shipped, "no sigma rules found"
    assert shipped <= fired_rules, f"rules never fired: {shipped - fired_rules}"


# --------------------------------------------------------------------------- #
# Sigma rule files are well-formed
# --------------------------------------------------------------------------- #
def test_rules_have_required_metadata():
    rules = load_rules(SIGMA_DIR)
    assert len(rules) == 4
    for rule in rules:
        assert rule.id, f"{rule.path} missing id"
        assert rule.title, f"{rule.path} missing title"
        assert rule.level in {"low", "medium", "high", "critical"}, rule.level
        assert "condition" in rule.detection


# --------------------------------------------------------------------------- #
# Sigma-lite engine unit tests
# --------------------------------------------------------------------------- #
def _rule(detection: dict) -> Rule:
    return Rule(id="t", title="t", level="high", logsource={}, detection=detection)


def test_cidr_modifier():
    rule = _rule({"sel": {"dst_ip|cidr": ["10.0.0.0/8", "169.254.0.0/16"]}, "condition": "sel"})
    assert rule.matches({"dst_ip": "169.254.169.254"})
    assert rule.matches({"dst_ip": "10.9.9.9"})
    assert not rule.matches({"dst_ip": "8.8.8.8"})
    assert not rule.matches({"dst_ip": "not-an-ip"})


def test_string_modifiers_case_insensitive():
    rule = _rule({"sel": {"uri|contains": "/META-DATA/"}, "condition": "sel"})
    assert rule.matches({"uri": "/latest/meta-data/iam"})
    startswith = _rule({"sel": {"origin|startswith": "https://"}, "condition": "sel"})
    assert startswith.matches({"origin": "HTTPS://evil.example"})
    endswith = _rule({"sel": {"query|endswith": ".internal"}, "condition": "sel"})
    assert endswith.matches({"query": "db.INTERNAL"})


def test_numeric_and_regex_modifiers():
    ttl = _rule({"sel": {"ttl|lte": 60}, "condition": "sel"})
    assert ttl.matches({"ttl": 5})
    assert not ttl.matches({"ttl": 3600})
    rx = _rule({"sel": {"origin|re": r"^https?://(?!localhost)"}, "condition": "sel"})
    assert rx.matches({"origin": "https://evil.example"})
    assert not rx.matches({"origin": "http://localhost:3000"})


def test_null_matches_absent_field():
    rule = _rule({"sel": {"origin": None}, "condition": "sel"})
    assert rule.matches({"dst_ip": "127.0.0.1"})
    assert not rule.matches({"origin": "https://evil.example"})


def test_condition_boolean_logic():
    detection = {
        "a": {"x": "1"},
        "b": {"y": "2"},
        "c": {"z": "3"},
        "condition": "a and (b or not c)",
    }
    rule = _rule(detection)
    assert rule.matches({"x": "1", "y": "2", "z": "9"})  # a and b
    assert rule.matches({"x": "1", "y": "9", "z": "9"})  # a and not c
    assert not rule.matches({"x": "1", "y": "9", "z": "3"})  # a but (not b and c)
    assert not rule.matches({"x": "9", "y": "2", "z": "9"})  # not a


def test_condition_quantifiers():
    detection = {
        "selection_a": {"x": "1"},
        "selection_b": {"y": "2"},
        "condition": "1 of selection_*",
    }
    assert _rule(detection).matches({"x": "1"})
    assert not _rule(detection).matches({"x": "9", "y": "9"})
    detection["condition"] = "all of them"
    assert _rule(detection).matches({"x": "1", "y": "2"})
    assert not _rule(detection).matches({"x": "1", "y": "9"})


def test_selection_list_is_or():
    rule = _rule({"sel": [{"a": "1"}, {"b": "2"}], "condition": "sel"})
    assert rule.matches({"a": "1"})
    assert rule.matches({"b": "2"})
    assert not rule.matches({"a": "9", "b": "9"})


# --------------------------------------------------------------------------- #
# Suricata linter
# --------------------------------------------------------------------------- #
def test_suricata_rules_are_structurally_valid():
    errors = suricata_lint.lint_rules(SURICATA_RULES)
    assert errors == [], errors
    assert suricata_lint.count_rules(SURICATA_RULES) >= 6


def test_suricata_linter_catches_bad_rules(tmp_path):
    bad = tmp_path / "bad.rules"
    bad.write_text('alert http any any -> any any (msg:"no sid";)\n')
    assert any("sid" in e for e in suricata_lint.lint_rules(bad))


# --------------------------------------------------------------------------- #
# Live-output adapters (the make validate-live path)
# --------------------------------------------------------------------------- #
def test_ssrf_probe_adapter_feeds_a_firing_event():
    sample = (
        "[2/4] simulating pre-fix "
        "fetch(http://127.0.0.1:54321/latest/meta-data/iam/security-credentials/role/) ...\n"
        "        vulnerable (AKIA-FAKE token in response): True\n"
    )
    events = adapters.parse_ssrf_probe(sample)
    assert len(events) == 1
    imds = next(
        r for r in load_rules(SIGMA_DIR) if r.path.stem == "mcp_ssrf_imds_credential_egress"
    )
    assert imds.matches(events[0])


def test_dns_rebind_probe_adapter_feeds_firing_events():
    sample = (
        "[+] probe 1: legitimate request (Origin: http://localhost:3000)\n"
        "    -> status=200, body shape: mcp-initialize\n"
        "[+] probe 2: request with hostile Origin: http://evil.example\n"
        "    -> status=200, body shape: mcp-initialize\n"
        "[+] probe 3: request with hostile Host: evil.example\n"
        "    -> status=200, body shape: mcp-initialize\n"
    )
    events = adapters.parse_dns_rebind_probe(sample)
    assert len(events) == 2  # probe 1 (legit) is intentionally not emitted
    rule = next(
        r for r in load_rules(SIGMA_DIR) if r.path.stem == "mcp_dns_rebind_origin_host_mismatch"
    )
    assert all(rule.matches(e) for e in events)

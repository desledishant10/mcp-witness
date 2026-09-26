"""mcp-witness detections: defender signatures for the disclosed MCP vuln
classes, plus a self-contained validator that proves each rule fires on the
attack and stays quiet on benign traffic.

Layout:
  sigma/            portable Sigma rules (one per detection)
  suricata/         network signatures for the same classes
  fixtures/         event fixtures modeled on real PoC output
  validation.yml    ground truth: which rules must fire on which events
  sigma_lite.py     dependency-free evaluator for the Sigma subset used here
  suricata_lint.py  structural linter for the Suricata rules
  adapters.py       parse live PoC output into normalized events
  validate.py       the `mcp-witness-detect` entry point
"""

"""The fuzzing oracle: decide whether a response indicates a bug.

Pure function over a CallResult. Distinguishes a real vulnerability signal
(sensitive file content, cloud-metadata content, command output), an
information leak (a stack trace in the response), a robustness failure (crash
or hang), and the healthy case where the server cleanly rejected bad input.
"""

from __future__ import annotations

import re

from fuzzer.models import (
    COMMAND_INJECTION,
    CRASH,
    ERROR_LEAK,
    HANG,
    OK,
    REJECTED,
    SENSITIVE_READ,
    SQL_ERROR,
    SSRF_HIT,
    CallResult,
)

_PASSWD = re.compile(r"root:.*?:0:0:", re.DOTALL)
_ID_OUTPUT = re.compile(r"uid=\d+\([^)]*\)\s+gid=\d+")
_TRACEBACK = re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+, in ")
_WIN_INI = "[extensions]"
# Credential/metadata *body* markers only. Path components like
# "security-credentials" or "computeMetadata" are excluded on purpose: a failed
# fetch echoes the requested URL, and matching a path substring there produced
# false SSRF hits. These markers appear in a metadata *response body*, not a URL.
_IMDS_MARKERS = (
    "AccessKeyId",
    "SecretAccessKey",
    "aws_secret_access_key",
    '"ami-id"',
    '"instance-id"',
)
# Signatures that the outbound request failed, so any URL echoed back is not a
# leak. Matched case-insensitively.
_REQUEST_FAILED = (
    "connecterror",
    "failed to make",
    "failed to fetch",
    "connection attempts failed",
    "connection refused",
    "nodename nor servname",
    "name or service not known",
    "no route to host",
    "max retries exceeded",
)
_SQL_ERRORS = (
    "sqlite3.OperationalError",
    "SQL syntax",
    "syntax error at or near",
    "unrecognized token",
    "no such table",
)


def classify_outcome(result: CallResult) -> tuple[str, str, str]:
    """Return (outcome, severity, evidence)."""
    if result.crashed:
        return (CRASH, "high", "server process terminated on this input")
    if result.timed_out:
        return (HANG, "high", "server did not respond within the timeout")

    text = result.text or ""
    request_failed = any(sig in text.lower() for sig in _REQUEST_FAILED)

    if _ID_OUTPUT.search(text):
        return (COMMAND_INJECTION, "high", "shell command output (id) reflected in response")
    if _PASSWD.search(text):
        return (SENSITIVE_READ, "high", "/etc/passwd content returned")
    if _WIN_INI in text:
        return (SENSITIVE_READ, "high", "Windows win.ini content returned")
    if not request_failed and any(marker in text for marker in _IMDS_MARKERS):
        return (SSRF_HIT, "high", "cloud instance-metadata content returned")
    if _TRACEBACK.search(text):
        return (ERROR_LEAK, "medium", "unhandled exception / stack trace in response")
    if any(marker in text for marker in _SQL_ERRORS):
        return (SQL_ERROR, "medium", "raw database error surfaced to the caller")

    if result.is_error:
        return (REJECTED, "info", "server returned an error result (input rejected)")
    return (OK, "info", "")

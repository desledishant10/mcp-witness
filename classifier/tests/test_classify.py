"""Smoke tests for the Layer 1 classifier.

These exercise the obvious cases that downstream consumers depend on.
Calibration against a real-server corpus (see
docs/capability-classifier.md §Calibration plan) is a separate work item.
"""

from classifier import classify_server, classify_tool


def _tool(name: str, description: str = "", **schema_props) -> dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": schema_props,
        },
    }


def test_read_file_classifies_as_fs_read():
    t = _tool(
        "read_file", "Reads the contents of a file at the given path.", path={"type": "string"}
    )
    tc = classify_tool(t)
    assert tc.has_capability("fs_read")
    assert tc.parameter_roles["path"].role == "path"
    assert tc.parameter_roles["path"].confidence == "high"


def test_fetch_url_classifies_as_net_egress():
    t = _tool(
        "fetch_url",
        "Makes an HTTP GET request to the given URL.",
        url={"type": "string", "format": "uri"},
    )
    tc = classify_tool(t)
    assert tc.has_capability("net_egress")
    assert tc.parameter_roles["url"].role == "url"
    assert tc.parameter_roles["url"].confidence == "high"


def test_run_command_classifies_as_exec():
    t = _tool("run_command", "Executes a shell command on the host.", command={"type": "string"})
    tc = classify_tool(t)
    assert tc.has_capability("exec")
    assert tc.parameter_roles["command"].role == "command"


def test_get_api_key_classifies_as_secret_access():
    t = _tool(
        "get_api_key", "Returns the API key for the requested service.", service={"type": "string"}
    )
    tc = classify_tool(t)
    assert tc.has_capability("secret_access")


def test_write_file_classifies_as_fs_write():
    t = _tool(
        "write_file",
        "Writes content to a file at the given path.",
        path={"type": "string"},
        content={"type": "string"},
    )
    tc = classify_tool(t)
    assert tc.has_capability("fs_write")
    assert tc.parameter_roles["path"].role == "path"
    assert tc.parameter_roles["content"].role == "content"


def test_execute_sql_classifies_as_db_query():
    t = _tool("execute_sql", "Executes a SQL query against the database.", query={"type": "string"})
    tc = classify_tool(t)
    assert tc.has_capability("db_query")
    assert tc.parameter_roles["query"].role == "query"


def test_camel_case_name_tokenizes_correctly():
    t = _tool("readFile", "Reads the file at the path.", filePath={"type": "string"})
    tc = classify_tool(t)
    assert tc.has_capability("fs_read")


def test_ambiguous_name_only_is_low_confidence_or_empty():
    """A vague tool with no descriptive signals should not produce confident findings."""
    t = _tool("do_thing", "Does a thing.", id={"type": "string"})
    tc = classify_tool(t)
    assert all(c.confidence == "low" for c in tc.capabilities)


def test_overbroad_combination_detected():
    tools = [
        _tool("read_file", "Reads a file at the path.", path={"type": "string"}),
        _tool(
            "fetch_url",
            "Makes an HTTP request to the URL.",
            url={"type": "string", "format": "uri"},
        ),
    ]
    sc = classify_server(tools)
    assert "fs_read" in sc.server_capability_set
    assert "net_egress" in sc.server_capability_set
    rationales = {c.rationale for c in sc.overbroad_combinations}
    assert "exfil_pair" in rationales


def test_secret_plus_net_egress_flagged():
    tools = [
        _tool(
            "get_credential",
            "Returns the credential for the named service.",
            service={"type": "string"},
        ),
        _tool(
            "send_webhook",
            "Makes an HTTP POST request to the webhook URL.",
            url={"type": "string", "format": "uri"},
        ),
    ]
    sc = classify_server(tools)
    rationales = {c.rationale for c in sc.overbroad_combinations}
    assert "credential_exfil" in rationales


def test_has_capability_threshold():
    """has_capability defaults to medium+; low confidence does not satisfy."""
    t = _tool("find_something")  # 'find' is an fs_read name_token alone → low
    tc = classify_tool(t)
    assert not tc.has_capability("fs_read")  # medium threshold
    assert tc.has_capability("fs_read", min_confidence="low")

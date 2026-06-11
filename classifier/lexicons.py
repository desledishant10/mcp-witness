"""Lexicons for Layer 1 (lexical) capability classification.

Hand-curated keyword and pattern tables that drive name- and
description-based detection. Updates here are versioned with the
capability-classifier spec.
"""

from __future__ import annotations

# Parameter name (lowercase) -> role. Exact match → high confidence;
# substring match → medium.
PARAM_ROLE_DICT: dict[str, tuple[str, ...]] = {
    "path": ("path", "file", "filename", "filepath", "dir", "directory", "folder", "location"),
    "url": ("url", "uri", "link", "endpoint", "href", "address"),
    "command": ("cmd", "command", "argv", "shell_command", "script"),
    "query": ("query", "sql", "filter", "where", "search_query"),
    "host": ("host", "hostname", "server", "domain"),
    "content": ("body", "content", "data", "payload", "text_content"),
}

# JSON Schema `format` -> parameter role. Match → high confidence.
SCHEMA_FORMAT_ROLES: dict[str, str] = {
    "uri": "url",
    "iri": "url",
    "uri-reference": "url",
    "url": "url",
    "hostname": "host",
    "idn-hostname": "host",
    "ipv4": "host",
    "ipv6": "host",
}

# Capability lexicons. For each tag:
#   name_tokens   weak signal — any one token present in the tokenized name
#   name_combos   strong signal — all tokens in the tuple present in the name
#   desc_patterns strong signal — regex matched (re.search) against lowercased description
#   param_role    supporting signal — tool has a param classified into this role
CAPABILITY_LEXICONS: dict[str, dict] = {
    "fs_read": {
        # Added "search" after mcp-server-file-finder calibration — a tool literally
        # named `search` whose description was "Universal file search tool". The
        # reverse-order desc pattern below also targets the same case.
        "name_tokens": {
            "read",
            "cat",
            "ls",
            "glob",
            "grep",
            "head",
            "tail",
            "tree",
            "find",
            "search",
        },
        "name_combos": [
            ("list", "files"),
            ("list", "directory"),
            ("list", "dir"),
            ("get", "file"),
            ("fetch", "file"),
            ("load", "file"),
            ("read", "file"),
            ("show", "file"),
            ("open", "file"),
        ],
        "desc_patterns": [
            r"\breads?\b.{0,30}\bfile\b",
            # Expanded after mcp-server-git calibration to cover repo nouns
            # ("List Git branches") without losing the original fs nouns.
            # The (?<!\[) lookbehind was added after mcp-server-anki calibration
            # surfaced a FP on Python type annotations like `Optional[List[str]] - Tags`
            # where `List` matched `\blists?\b` and `Tags` matched the alternation.
            r"(?<!\[)\blists?\b(?![\[\(]).{0,30}\b(files?|director(y|ies)|contents?|branches?|commits?|tags?|repositor(y|ies))\b",
            r"\breturns? .{0,30}\bcontents?\b",
            r"\bgets? .{0,30}\bfile\b",
            r"\bopens? .{0,30}\bfile\b",
            # Calibration-driven (mcp-server-memory negative + example_server miss):
            # require a filesystem-context noun so "search the knowledge graph"
            # does not match while "search the workspace for files" does.
            r"\bsearch(es)?\b.{0,30}\b(files?|director(y|ies)|workspace)\b",
            # mcp-server-git calibration: "Shows the working tree status",
            # "Shows the commit logs", "Shows the contents of a commit" etc.
            r"\b(shows?|displays?)\b.{0,30}\b(status|diff|log|contents?|files?|director(y|ies)|trees?|branches?|commits?|tags?)\b",
            # mcp-server-file-finder calibration: "Universal file search tool" —
            # noun before verb. Complements the verb-before-noun search pattern
            # above so both orderings are covered.
            r"\b(files?|director(y|ies)|workspace)\b.{0,20}\bsearch(es)?\b",
        ],
        "param_role": "path",
    },
    "fs_write": {
        "name_tokens": {
            "write",
            "create",
            "delete",
            "remove",
            "rename",
            "move",
            "mkdir",
            "touch",
            "save",
            "edit",
            "patch",
        },
        "name_combos": [
            ("write", "file"),
            ("create", "file"),
            ("delete", "file"),
            ("save", "file"),
            ("update", "file"),
            ("modify", "file"),
        ],
        "desc_patterns": [
            r"\bwrites?\b.{0,30}(file|disk)",
            r"\bcreates?\b.{0,30}(file|directory)",
            r"\bdeletes?\b.{0,30}(file|directory)",
            r"\bsaves?\b.{0,30}(file|disk)",
            r"\bmodif(ies|y)\b.{0,30}file",
            r"\boverwrites?\b",
            # mcp-server-git calibration: distinguish repo-write tools from
            # repo-read tools when both share repo_path parameter.
            r"\brecords?\b.{0,30}\b(changes?|commits?)\b",
            r"\badds?\b.{0,30}\b(files?|contents?|staging|index)\b",
            r"\bcreates?\b.{0,30}\b(branches?|tags?|repositor(y|ies)|commits?)\b",
            r"\bswitches?\b.{0,30}\bbranches?\b",
            r"\bunstages?\b",
        ],
        "param_role": "path",
    },
    "net_egress": {
        "name_tokens": {"fetch", "http", "request", "download", "webhook", "scrape", "post", "put"},
        "name_combos": [
            ("send", "http"),
            ("send", "request"),
            ("get", "url"),
            ("fetch", "url"),
            ("call", "api"),
            ("send", "webhook"),
            ("http", "get"),
            ("http", "post"),
            ("make", "request"),
        ],
        "desc_patterns": [
            r"\bmakes? .{0,20}\bhttp\b",
            r"\bsends? .{0,20}(request|webhook|http)",
            r"\bfetches? .{0,20}(url|page|website|http)",
            r"\bdownloads?\b",
            r"\bcalls? .{0,20}(api|endpoint|url)",
            r"\bhttp[s]? request\b",
            r"\bissues? .{0,20}http\b",
        ],
        "param_role": "url",
    },
    "exec": {
        "name_tokens": {"exec", "execute", "shell", "bash", "eval", "sh"},
        "name_combos": [
            ("run", "command"),
            ("run", "script"),
            ("run", "shell"),
            ("execute", "command"),
            ("execute", "code"),
            ("shell", "exec"),
            ("eval", "code"),
        ],
        "desc_patterns": [
            r"\bexecutes? .{0,20}(command|script|code|shell)",
            r"\bruns? .{0,20}(command|script|shell|process)",
            r"\bevaluates? .{0,20}(code|expression)",
            r"\bshell\b",
        ],
        "param_role": "command",
    },
    "secret_access": {
        "name_tokens": {"secret", "credential", "token", "password", "keychain", "vault"},
        "name_combos": [
            ("get", "secret"),
            ("read", "credential"),
            ("get", "env"),
            ("read", "token"),
            ("get", "key"),
            ("get", "password"),
            ("fetch", "secret"),
            ("api", "key"),
        ],
        "desc_patterns": [
            r"\b(reads?|returns?|gets?|fetches?)\b.{0,30}(secret|credential|token|api\s*key|password)\b",
            r"\benvironment variable\b",
            r"\bkeychain\b",
            r"\bvault\b",
            r"\bcredentials?\b",
        ],
        "param_role": None,
    },
    "db_query": {
        "name_tokens": {"select"},
        "name_combos": [
            ("query", "database"),
            ("query", "db"),
            ("execute", "query"),
            ("execute", "sql"),
            ("select", "from"),
            ("db", "query"),
            ("sql", "query"),
            ("mongo", "find"),
            ("redis", "get"),
            ("run", "query"),
        ],
        "desc_patterns": [
            r"\bexecutes? .{0,20}(sql\s+)?query\b",
            r"\bqueries? .{0,20}database\b",
            r"\bselects? .{0,20}from\b",
            r"\b(reads?|fetches?|loads?) .{0,20}\bdatabase\b",
            r"\bsql\b.{0,20}\bquery\b",
        ],
        "param_role": "query",
    },
    "db_write": {
        "name_tokens": {"insert", "update", "drop", "alter"},
        "name_combos": [
            ("db", "insert"),
            ("db", "update"),
            ("sql", "insert"),
            ("sql", "update"),
            ("sql", "delete"),
            ("mongo", "insert"),
            ("redis", "set"),
            ("execute", "insert"),
        ],
        "desc_patterns": [
            r"\binserts? .{0,20}(database|table|record|row)",
            r"\bupdates? .{0,20}(database|table|record|row)",
            # Tightened from `\bdeletes? .{0,20}\bfrom\b` after mcp-server-memory
            # calibration produced a spurious db_write on "Delete relations
            # from the knowledge graph". Require an explicit DB noun nearby.
            r"\bdeletes? .{0,30}\b(table|database|record|rows?|collection)\b",
            r"\bdrops? .{0,20}(table|database|index)",
            r"\bwrites? .{0,20}database\b",
        ],
        "param_role": "query",
    },
}

# Server-level overbroad capability combinations. Each entry: (required tags, rationale).
OVERBROAD_COMBOS: list[tuple[tuple[str, ...], str]] = [
    (("fs_read", "net_egress"), "exfil_pair"),
    (("secret_access", "net_egress"), "credential_exfil"),
    (("db_query", "net_egress"), "database_exfil"),
    (("fs_write", "exec"), "write_then_execute"),
    (("db_query", "db_write"), "full_db_compromise_on_injection"),
]

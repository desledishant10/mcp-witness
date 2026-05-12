"""Shared fixtures for harness tests.

Most fixtures here build a `Target` pointing at the mock MCP server with
a specific tool set. The mock server is spawned as a subprocess via
stdio, so PYTHONPATH must include the project root for the subprocess
to import `harness.testing.mock_server`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture
def mock_target(tmp_path: Path):
    """Factory: (tools) -> Target pointing at the mock MCP server."""
    from harness.runner import Target

    def _build(tools: list[dict]):
        config_path = tmp_path / "mock_config.json"
        config_path.write_text(json.dumps({"tools": tools}))
        env = {
            **os.environ,
            "PYTHONPATH": f"{PROJECT_ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
            "MCPSCAN_MOCK_CONFIG": str(config_path),
            "PYTHONUNBUFFERED": "1",
        }
        return Target(
            command=sys.executable,
            args=["-m", "harness.testing.mock_server"],
            env=env,
        )

    return _build

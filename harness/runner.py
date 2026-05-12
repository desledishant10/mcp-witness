"""Scenario runner: setup → attack → oracle → cleanup.

The runner auto-selects between direct mode and proxy mode based on the
scenario's attack steps. Direct mode uses TracedMCPClient against the
target server (no agent involved). Proxy mode additionally instantiates
a ProxySession plus an agent driver — required by scenarios that test
agent-side trust (description injection, output injection, rug pull).
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from classifier import classify_tool

from .agents import AgentDriver, AnthropicAgent, StubAgent
from .canaries import CanaryServer
from .macros import substitute
from .mcp_client import TracedMCPClient
from .proxy import ProxySession, ToolDescOverride, ToolOutputOverride
from .scenario import Scenario

log = logging.getLogger(__name__)

_PROXY_STEPS = {
    "inject_tool_description", "inject_tool_output", "inject_resource_content",
    "mutate_tool_definition", "send_user_message", "wait", "sampling_handler",
}


@dataclass
class RunResult:
    scenario_id: str
    passed: bool                            # True = no vulnerability evidence
    oracle_evidence: list[str] = field(default_factory=list)
    skipped_steps: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Target:
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


async def run_scenario(scenario_path: Path, target: Target,
                       agent_factory: Callable[[], AgentDriver] | None = None) -> RunResult:
    spec = yaml.safe_load(scenario_path.read_text())
    scn = Scenario.model_validate(spec)
    if _needs_proxy_mode(scn):
        factory = agent_factory or (lambda: StubAgent())
        return await _run_proxy_mode(scn, target, factory)
    return await _run_direct_mode(scn, target)


def _needs_proxy_mode(scn: Scenario) -> bool:
    return any(s.step in _PROXY_STEPS for s in scn.attack)


def make_agent_factory(kind: str) -> Callable[[], AgentDriver]:
    """Return a zero-arg factory producing the requested agent driver kind."""
    if kind == "stub":
        return lambda: StubAgent()
    if kind == "anthropic":
        return lambda: AnthropicAgent()
    raise ValueError(f"unknown agent kind: {kind!r} (use 'stub' or 'anthropic')")


def _init_ctx(scn: Scenario, canaries: CanaryServer) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "run_id": secrets.token_hex(4),
        "canaries": {},
        "fixtures": {},
        "captures": {},
    }
    for c in scn.setup.canaries:
        ctx["canaries"][c.id] = canaries.allocate(c.id)
    return ctx


async def _run_direct_mode(scn: Scenario, target: Target) -> RunResult:
    canaries = CanaryServer()
    await canaries.start()
    ctx = _init_ctx(scn, canaries)
    skipped: list[str] = []
    error: str | None = None
    try:
        _setup_fixtures(scn, ctx)
        async with TracedMCPClient(target.command, target.args, target.env) as client:
            for step in scn.attack:
                kind = step.step
                if kind in _PROXY_STEPS:
                    log.warning("skipping %s — proxy step in direct-mode scenario", kind)
                    skipped.append(kind)
                    continue
                await _dispatch(step.model_dump(), client, ctx)
            evidence = _evaluate_oracle(scn.oracle, client.trace, ctx)
        return RunResult(
            scenario_id=scn.id,
            passed=len(evidence) == 0,
            oracle_evidence=evidence,
            skipped_steps=skipped,
            error=error,
        )
    finally:
        _cleanup_fixtures(scn, ctx)
        await canaries.stop()


async def _run_proxy_mode(scn: Scenario, target: Target,
                          agent_factory: Callable[[], AgentDriver]) -> RunResult:
    canaries = CanaryServer()
    await canaries.start()
    ctx = _init_ctx(scn, canaries)
    skipped: list[str] = []
    error: str | None = None
    evidence: list[str] = []
    try:
        _setup_fixtures(scn, ctx)
        # Construct the agent BEFORE entering the proxy context so an
        # agent-init failure (missing module, missing API key) surfaces
        # as itself rather than getting wrapped in an unhelpful
        # ExceptionGroup by anyio's proxy-cleanup task group.
        agent = agent_factory()
        async with ProxySession(target.command, target.args, target.env) as proxy:
            for step in scn.attack:
                try:
                    await _dispatch_proxy_step(step.model_dump(), proxy, agent, ctx)
                except NotImplementedError as e:
                    log.warning("step %s: %s", step.step, e)
                    skipped.append(step.step)
            evidence = _evaluate_oracle(scn.oracle, proxy.trace, ctx)
    except Exception as e:                                  # noqa: BLE001
        log.exception("proxy-mode scenario failed")
        error = f"{type(e).__name__}: {e}"
    finally:
        _cleanup_fixtures(scn, ctx)
        await canaries.stop()
    return RunResult(
        scenario_id=scn.id,
        passed=len(evidence) == 0 and error is None,
        oracle_evidence=evidence,
        skipped_steps=skipped,
        error=error,
    )


async def _dispatch_proxy_step(step: dict[str, Any], proxy: ProxySession,
                                agent: AgentDriver, ctx: dict[str, Any]) -> None:
    kind = step["step"]
    if kind == "inject_tool_description":
        proxy.state.desc_overrides.append(ToolDescOverride(
            target=step.get("target_tool", "*"),
            mode=step.get("mode", "append"),
            payload=substitute(step["payload"], ctx),
        ))
        return
    if kind == "inject_tool_output":
        payload = step["payload"]
        text = payload["content"] if isinstance(payload, dict) else str(payload)
        proxy.state.output_overrides.append(ToolOutputOverride(
            target=step.get("target_tool", "*"),
            when=step.get("when", "every_call"),
            payload_text=substitute(text, ctx),
        ))
        return
    if kind == "mutate_tool_definition":
        proxy.state.desc_overrides.append(ToolDescOverride(
            target=step.get("target_tool", "*"),
            mode="replace",
            payload=substitute(step["new_description"], ctx),
        ))
        if step.get("emit_changed_notification"):
            proxy.notify_tools_changed()
        return
    if kind == "send_user_message":
        await agent.send_message(substitute(step["content"], ctx), proxy)
        return
    if kind == "wait":
        # Agent drivers are synchronous within send_message, so `agent_idle`
        # is implicit by the time we get here. Honor explicit timeouts as a
        # capped literal sleep so scenarios can throttle if they want to.
        if step.get("for") == "agent_idle":
            return
        await asyncio.sleep(min(step.get("timeout_seconds", 1), 10))
        return
    if kind == "tools_list":
        # Captures the agent-visible view of tools at this point (post any
        # mutations queued so far).
        result_tools = await proxy.list_tools_for_agent()
        if step.get("capture_as"):
            ctx["captures"][step["capture_as"]] = result_tools
        return
    if kind == "tools_call":
        # Direct probe still works inside a proxy-mode scenario; uses the
        # target client directly, bypassing the agent.
        assert proxy.target_client is not None
        await _run_tools_call(step, proxy.target_client, ctx)
        return
    if kind == "sampling_handler":
        raise NotImplementedError("sampling_handler is not implemented in v0.2")
    if kind in {"resources_read", "resources_list"}:
        raise NotImplementedError(f"{kind} is not implemented in v0.2")
    raise ValueError(f"unknown step type: {kind}")


async def _dispatch(step: dict[str, Any], client: TracedMCPClient, ctx: dict[str, Any]) -> None:
    kind = step["step"]
    if kind == "tools_list":
        result = await client.list_tools()
        if step.get("capture_as"):
            ctx["captures"][step["capture_as"]] = result
        return
    if kind == "tools_call":
        await _run_tools_call(step, client, ctx)
        return
    if kind in {"resources_read", "resources_list"}:
        log.warning("skipping %s (not implemented in v0.1)", kind)
        return
    raise ValueError(f"unknown step type: {kind}")


async def _run_tools_call(step: dict[str, Any], client: TracedMCPClient,
                          ctx: dict[str, Any]) -> None:
    tools = (await client.list_tools()).tools
    cap = step.get("target_tool_capability")
    if cap:
        matched = [t for t in tools if _has_capability(t, cap)]
    else:
        target_glob = step.get("target_tool", "*")
        matched = [t for t in tools if fnmatch.fnmatchcase(t.name, target_glob)]

    payloads = step.get("payloads") or [None]
    for tool in matched:
        for payload in payloads:
            iter_ctx = {**ctx, "payload": payload} if payload is not None else ctx
            args = _build_args(step, tool, iter_ctx)
            try:
                await client.call_tool(tool.name, args)
            except Exception as e:  # noqa: BLE001
                log.debug("call failed (often intended): %s(%s) -> %s", tool.name, args, e)


def _build_args(step: dict[str, Any], tool: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    for k, v in (step.get("arguments") or {}).items():
        k_clean = k.lstrip("$.")    # tolerate "$.path" or "path"
        args[k_clean] = substitute(str(v), ctx) if isinstance(v, str) else v

    # argument_role: pick the first string-typed parameter as the injection
    # target. A real implementation consults the classifier; v0.1 uses
    # parameter type + name heuristics so MCP-D-002/003 work today.
    role = step.get("argument_role")
    if role and ctx.get("payload") is not None:
        param = _pick_param_by_role(tool, role)
        if param:
            args[param] = substitute(str(ctx["payload"]), ctx)
    return args


def _classify(tool: Any):
    return classify_tool({
        "name": getattr(tool, "name", ""),
        "description": getattr(tool, "description", "") or "",
        "inputSchema": getattr(tool, "inputSchema", None) or {},
    })


def _has_capability(tool: Any, cap: str) -> bool:
    return _classify(tool).has_capability(cap)


def _pick_param_by_role(tool: Any, role: str) -> str | None:
    tc = _classify(tool)
    for conf in ("high", "medium"):
        for pname, prole in tc.parameter_roles.items():
            if prole.role == role and prole.confidence == conf:
                return pname
    return None


def _evaluate_oracle(oracle, trace, ctx) -> list[str]:
    """Non-empty return means the attack succeeded (vulnerability present)."""
    for cond in oracle.all_of:
        if not _evaluate_condition(cond, trace, ctx):
            return []
    evidence: list[str] = []
    for cond in oracle.any_of:
        e = _evaluate_condition(cond, trace, ctx)
        if e:
            evidence.append(e)
    return evidence


def _evaluate_condition(cond: dict[str, Any], trace, ctx) -> str | None:
    if "canary_hit" in cond:
        c = cond["canary_hit"]
        canary = ctx["canaries"].get(c["id"])
        if canary and len(canary.hits) >= c.get("min_count", 1):
            return f"canary_hit:{c['id']}:hits={len(canary.hits)}"
        return None
    if "trace_contains" in cond:
        c = cond["trace_contains"]
        pat = substitute(c["pattern"], ctx)
        n = trace.matches(pat, where=c.get("where", "any"))
        if n > 0:
            return f"trace_contains:{pat!r}:n={n}"
        return None
    if "tool_call_matches" in cond:
        c = cond["tool_call_matches"]
        # JSONPath evaluation is a v0.2 item. v0.1 does a substring scan of
        # the request payload — adequate for canary-URL detection.
        needle = substitute(c.get("value_contains", ""), ctx)
        rx = re.compile(c.get("tool_name_regex", ".*"))
        for f in trace.frames:
            if f.direction == "out" and f.method == "tools/call":
                if rx.search(f.payload.get("name", "")) and needle in str(f.payload):
                    return f"tool_call_matches:{f.payload['name']}:contains={needle!r}"
        return None
    if "no_user_consent_prompt" in cond:
        # Only meaningful in agent / proxy mode; v0.1 trivially satisfies.
        return "no_user_consent_prompt:n/a-in-direct-mode"
    return None


def _setup_fixtures(scn: Scenario, ctx: dict[str, Any]) -> None:
    for fx in scn.setup.fixtures:
        path = substitute(fx.path, ctx)
        Path(path).write_text(substitute(fx.content, ctx))
        ctx["fixtures"][fx.id] = path


def _cleanup_fixtures(scn: Scenario, ctx: dict[str, Any]) -> None:
    for fx in scn.setup.fixtures:
        p = ctx["fixtures"].get(fx.id)
        if p:
            Path(p).unlink(missing_ok=True)

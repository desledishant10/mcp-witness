# Detector evolution: how MCP-S-014 went from one of five to four of four

MCP-S-014 is the static rule in mcp-witness that catches HTTP-transport MCP servers that bind to a network address without validating Origin or Host headers on inbound requests. Those servers are vulnerable to DNS rebinding. An attacker page on a domain whose DNS the attacker controls can flip the resolved IP to point at the victim machine, making the browser believe it's still talking to the original origin while the request actually hits the victim's MCP server on localhost.

I wrote v0.2 of the rule in early May 2026. Then in mid-May I ran the DNS-rebinding survey across five PyPI-published Python MCP servers that ship an HTTP transport. The detector hit on one of them. The other four were vulnerable by manual source review. That's the kind of result that makes you stop and look at why your detector is wrong, rather than ship it as-is.

This is the story of how MCP-S-014 went from one of five to four of four. Four patches: W1, W2, W3, W4. None of them came from theory. Each one was a specific source file in front of me showing me a thing the detector had no idea how to handle.

## W1: host bound to a variable

`mcp-streamablehttp-proxy` v0.2.0 has this:

```python
def serve(host: str = "127.0.0.1", port: int = 3000) -> None:
    ...
    uvicorn.run(app, host=host, port=port)
```

The detector's job was to look at every `uvicorn.run` call site, read the `host` kwarg, and decide whether the value was a loopback address or a network-reachable bind. In v0.2 I only resolved string literals. Here, `host` is a function parameter with a default. The literal `"127.0.0.1"` exists in the AST as the default value of an `ast.arg`, not as the keyword argument to `uvicorn.run`.

The fix was a pre-pass over the module that collects all the string bindings it can find. `ast.Assign` nodes with a single Name target and a Constant string value. `FunctionDef` args with string defaults, including keyword-only args. Then when the call-site extractor sees `host=host`, it looks the name up in the binding map.

```python
def _collect_string_bindings(tree: ast.Module) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if isinstance(tgt, ast.Name) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    bindings[tgt.id] = node.value.value
        elif isinstance(node, ast.FunctionDef):
            for arg, default in _zip_args_defaults(node.args):
                if isinstance(default, ast.Constant) and isinstance(default.value, str):
                    bindings[arg.arg] = default.value
    return bindings
```

I picked file-wide flat scope over proper lexical scope handling on purpose. This is a "review this code" rule, not a sound type checker. The cost of a false positive when two different functions both define a local called `host` with different values is some reviewer time. The cost of missing the real bug is shipping a tool that doesn't catch what it's supposed to catch. The asymmetry made the call easy.

W1 alone caught three of the four missed packages.

## W2: the keyword suppression that ate itself

The rule had a "don't fire if the file mentions Origin" suppression. The intent was reasonable. If the maintainer is checking Origin headers somewhere, the file probably has an Origin validation pattern I can't easily detect, so I shouldn't false-positive on it. The implementation was a case-insensitive substring match on the whole file.

`mcp-fetch-streamablehttp-server` has this in its transport response code:

```python
return (
    200,
    {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        ...
    },
    ...
)
```

That response header isn't a validation. It's the literal opposite. It tells browsers that any origin is allowed to read responses from this server. The presence of that line in the file should have made the detector more confident the file is vulnerable, not less. Instead the substring match saw "Origin" and went quiet.

I rewrote the suppression to walk the AST for actual request-header reads. A `Subscript` on a headers expression with the key `"Origin"`, or a method call `.headers.get("Origin", ...)`. Case-insensitive on the key. Comments and docstrings no longer count. Response-header string literals no longer count. The suppression now requires the code to actually look at the request's Origin, not just to mention the word somewhere.

There's a deeper lesson in W2 about substring matching on source code. Any keyword that means "I'm doing the right thing" in one position can mean "I'm doing the wrong thing" in another position. The fix isn't a better keyword list. The fix is to stop matching keywords and start matching shapes. Every "suppress if file contains X" check I have in the codebase is a candidate for the same rewrite.

## W3: a framework I hadn't accounted for

`mcp-server-fetch-sse` uses aiohttp instead of FastAPI or Starlette. The bind happens via `web.TCPSite`, not `uvicorn.run`:

```python
runner = web.AppRunner(app)
await runner.setup()
site = web.TCPSite(runner, "localhost", port)
await site.start()
```

The v0.2 detector had a list of known server-bind methods: `uvicorn.run`, `FastAPI(...).run`, `Starlette(...).run`, `http.server.HTTPServer`, and a few others. It had no entry for aiohttp.

This was the easiest patch in absolute terms (add two entries to a list) and the most humbling in what it taught me. Every static rule I write is implicitly a list of frameworks I happen to know about. The `mcp-server-fetch-sse` package isn't obscure. aiohttp isn't obscure. I just hadn't sat down to enumerate every Python HTTP server framework I'd need to cover. I had bias toward the ones that show up in the Anthropic reference implementations, because those are the ones I'd read most carefully.

The fix added `web.run_app` (keyword-host pattern) and `web.TCPSite` (positional-host pattern, where host is the second positional argument) to the bind-method list. The TCPSite pattern was the more interesting one because the host is positional, not a keyword, and the rule extractor needed to handle both shapes for the same method-name list.

Lesson banked. When I add a new framework entry now, I grep the top 200 PyPI packages by download count for that import and see what bind shapes show up. Not perfect. It's more coverage than "frameworks I personally remember", which was effectively the v0.2 policy.

## W4: env-default resolution, surfaced after W1

I shipped W1, W2, W3 together and re-ran the detector against the survey targets. It fired on three of four. One of the four was `mcp-fetch-streamablehttp-server`, and I expected W1 to catch it because I'd seen the same `uvicorn.run(host=host)` shape in its source. The detector was silent.

Reading the source again:

```python
host = os.getenv("HOST", "0.0.0.0")  # noqa: S104
port = int(os.getenv("PORT", "3000"))
uvicorn.run(app, host=host, port=port)
```

(Note the `# noqa: S104`. That's a Bandit suppression for binding to all interfaces. The maintainer was told this was a flagged pattern, by a different tool, and chose to suppress the warning. I'll come back to that observation in the disclosure record itself.)

W1 was working. It saw `host=host` in the call and looked up `host` in the binding map. The binding map didn't have `host` because the assignment wasn't `host = "0.0.0.0"`. It was `host = os.getenv("HOST", "0.0.0.0")`, which the binding collector didn't know how to read.

W4 added `_extract_env_default`. When the binding collector hits an `ast.Assign` whose value is a `Call`, it checks whether the call is `os.getenv` or `os.environ.get`, then takes the second positional argument as the string default and binds the assignee to that. After W4, `host` correctly binds to `"0.0.0.0"` and the rule fires.

The interesting part of W4 is when it surfaced. Not from the survey. From verifying my own fix. I'd assumed W1 would catch this package. The verification step showed it didn't. If I'd shipped W1 through W3 without re-running against every original target, I would have called the survey "complete" with one finding still silently missed.

That changed how I sequence patches now. Every detector fix gets re-run against the full set of targets that originally motivated any rule in the file, not just the target the current patch was about. Patches expose other patches. You have to give the second-order ones a chance to show up before you ship.

## A walker bug that silently broke audit for the whole v0.2 lifecycle

This one doesn't fit the W1 through W4 numbering, but it's the same lesson in a different shape, and it cost me a day to find. Worth banking.

The audit walker had a skip list for things like `/site-packages/` and `/.venv/`. The check was a substring match against the absolute path of every file. When I ran `mcp-witness-audit some-package`, the walker would pip-install the package into a temp venv, then point the analyzer at the install path, which was something like `/tmp/whatever/site-packages/some_package/`. Every file's absolute path contained `/site-packages/`. The walker skipped every file. Zero results.

This was the documented quickstart workflow for the entire v0.2 release. I caught it during the v0.3 re-verification pass when running the patched detector against the survey targets returned zero hits despite my unit tests passing. The unit tests pointed at fixtures inside the repo, not at pip-installed packages, so they didn't exercise the path-prefix shape that broke in the real workflow.

The fix is one line. Check skip fragments against the path relative to the scan root, not the absolute path. The lesson is bigger. A tool that's silently broken for its documented quickstart is the same outcome, in user-experience terms, as a tool that doesn't exist. The unit tests gave me high confidence in a workflow that didn't actually work. Integration tests against the actual pip-installed shape would have caught it on day one.

## What I'd say to anyone building a static rule for a real ecosystem

Four patches to MCP-S-014 between v0.2 and v0.3. Three came from a real survey. One came from re-verifying my own fixes. One walker bug came from the same re-verification pass. None came from sitting down and brainstorming "what could go wrong."

If you're building a static analyzer for a real ecosystem, the cycle that actually works for me looks like this. Write the rule against the patterns you've seen. Run it against a survey of real packages in the ecosystem you care about. The misses are the real test. Every miss is a patch with a name attached to it, motivated by a specific file you can point at. Then re-verify after every patch round, because patches expose other patches, and the second-order ones won't show up if you stop after round one.

Rules with that lineage attached to them are more legible to other people than rules with just "I thought of this" attached. When a future contributor reads MCP-S-014's lexicon decisions in the source, they're reading: this exists because `mcp-streamablehttp-proxy` was missed. This exists because `mcp-fetch-streamablehttp-server` was missed. The detector's history is the disclosure track's history, and each is a citation for the other.

That's the artifact I want this writeup to leave behind. The story of the rule going from one of five to four of four. Not as a victory lap. As a worked example of how a static rule actually gets to be right about the real world, which in my experience never looks like sitting down and getting it right the first time.

## What this writeup doesn't cover

A few honest gaps, so this doesn't read as a finished story it isn't.

The rule still has a fifth weakness I haven't patched. Some packages embed the bind logic inside a class method whose `self` references are arguments at construction time. The binding collector is module-flat and doesn't follow that indirection. I haven't yet hit a real MCP package that misses for this reason. When I do, that becomes W5.

The rule is Python-only. The same vulnerability class exists in TypeScript MCP servers, and I haven't written a TS analyzer yet (it's deferred until post-embargo). If you're reading this and you maintain a TS-side MCP server, the same Origin-validation question applies and the manual source-review version is fast.

And the survey itself is one slice of the ecosystem at one point in time. I picked HTTP-transport packages. There are other transport surfaces in MCP (stdio is the common one, plus the streamable-HTTP variants that themselves wrap HTTP). The vulnerability class is specific to HTTP. The methodology generalizes.

The point of writing this up was to make the methodology itself reusable, separate from the specific rule. If you're writing a different static rule for a different ecosystem, the W1 through W4 names don't matter. The cycle does.

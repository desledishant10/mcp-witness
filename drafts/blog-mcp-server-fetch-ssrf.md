# I found an SSRF in Anthropic's reference MCP server, proved it on EC2, and the verified fix is still unmerged

**Dishant Desle**

I build a security scanner for Model Context Protocol servers. One of the first things it flagged was Anthropic's own reference server. I proved the finding on a real EC2 instance with live IAM credentials, filed a coordinated disclosure, and an external contributor opened a clean fix ten days later. I verified that fix against the same demo that had leaked the credentials. As of today, four months after I filed, the issue is closed as "not planned," the fix PR is still open with green CI and no approving review, and the vulnerable code has kept shipping to PyPI. The patch has never merged, so no release can carry it. The version you install today still runs the same unguarded fetch path I reported.

This is the whole arc, start to finish. The way it ended is more instructive than the bug itself, so I am going to tell all of it.

## The flag

The scanner is [mcp-witness](https://github.com/desledishant10/mcp-witness), an Apache-2.0 toolkit I built for auditing MCP servers: a static analyzer over the captured `tools/list`, a dynamic harness that drives a live server, and a small capability classifier. The static rule that fired here is MCP-S-009. It looks for a URL-fetching tool with no apparent constraint on where it can point: a parameter named `url` (or `uri`, or `endpoint`, or typed `format: uri`), no JSON Schema `pattern` / `const` / `enum` on that parameter, and no validation language in the tool description. It is a heuristic. It tells you where to look next, not that anything is exploitable.

Run against `mcp-server-fetch` v2025.4.7, the reference `fetch` server from the `modelcontextprotocol/servers` repo, MCP-S-009 flagged the single `fetch` tool: a bare-string `url` parameter with no schema constraint and nothing in the description promising a scheme allowlist or a host denylist. The implementation underneath is about as small as an HTTP tool gets. It takes the URL from the agent's tool-call arguments and passes it to an `httpx` `AsyncClient.get(url)`. No scheme allowlist. No IP-class denylist. No redirect validation. On a cloud host where the instance metadata service (IMDS) is reachable, that is a credential-exfiltration primitive. An agent coerced through prompt injection into calling `fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/")` gets back live IAM credentials in the response body. The MCP threat model explicitly includes adversarially influenced tool arguments, so "the agent decides where to point it" is not a defense. It is the attack surface.

## The accidental defense that fooled me first

When I ran the dynamic probe (MCP-D-003) on my laptop, every metadata URL failed, each one returning `"Failed to fetch robots.txt ... due to a connection issue"`. It looked defended. It was not. What I was looking at is a "defense" that holds on exactly the machines where it does not matter and fails open on exactly the machines where it does.

Before `fetch` retrieves the URL you asked for, it retrieves that host's `robots.txt` first, out of politeness. The logic decomposes cleanly:

1. `fetch` issues a `GET /robots.txt` to the target host.
2. If that GET produces any HTTP response at all, including a 404, `fetch` proceeds to the requested URL.
3. If that GET fails at the network layer (connection refused, timeout, an unsupported scheme), `fetch` aborts and returns the "Failed to fetch robots.txt" error.

On my laptop, `169.254.169.254` is not routable. The `robots.txt` fetch never completes a TCP handshake, step 3 fires, and the tool bails before it ever touches the metadata URL. To a local auditor that reads as an SSRF guard. It is not one. It is a side effect of a courtesy check that only "protects" you because the dangerous host happens to be unreachable from where you are sitting.

Flip the environment and the accident inverts. On a cloud instance the metadata service answers TCP on `169.254.169.254`. It has no `robots.txt`, so it returns a 404, an HTTP response that satisfies step 2, and `fetch` sails past the courtesy check to fetch the real metadata URL. The one thing between the agent and the credential endpoint is a check that passes the moment the target is a host worth attacking. The `--ignore-robots-txt` flag that ships with the tool removes even this accidental behavior, so an operator who sets it (a legitimate choice when scraping sites with broken robots files) has nothing at all in front of the metadata service.

I could reason about all of this, but reasoning is not a demonstration. So I built one.

## The EC2 proof

On 2026-05-12 I launched a `t3.micro` (Amazon Linux 2023, us-east-1), attached an IAM role granting `AmazonEC2ReadOnlyAccess`, and set the instance metadata options to IMDSv2 Optional. I installed `mcp-server-fetch`, drove it through a short MCP client harness, and asked the `fetch` tool for the IMDS credentials URL.

It came back redacted like this:

```
--- calling fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/') ---

Contents of http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/:
{
  "Code" : "Success",
  "AccessKeyId" : "ASIA****",
  "SecretAccessKey" : "wJal****",
  "Token" : "AQoD****",
  "Expiration" : "2026-05-12T..."
}
```

A complete, valid AWS IAM credential triplet, returned by an MCP tool, retrievable by anything that can talk an agent into calling `fetch` with a metadata URL. I tore the role and the instance down within minutes of capture; the credentials expired on their normal lifetime, and the unredacted output was never committed anywhere.

## What I will not overclaim

The honest caveat matters, and I stated it in the disclosure before anyone asked. On Amazon Linux 2023 with the default IMDSv2-Required setting, this SSRF is fully mitigated at the host level. `mcp-server-fetch` does not send the `X-aws-ec2-metadata-token` header that IMDSv2 requires, so a properly configured IMDS answers 401 and nothing leaks. My EC2 demo deliberately set IMDSv2 to Optional to exercise the vulnerable path.

The bug is still real, for reasons that outlive one AMI default:

- IMDSv2 is not Required on older AMIs, and plenty of running instances predate the default.
- Operators legitimately set it to Optional for compatibility with IMDSv1 tooling.
- GCP and Azure metadata services have different default postures.
- RFC 1918 internal services (databases, admin panels, in-cluster APIs) have no IMDSv2 equivalent at all.

A host-level mitigation you do not control is defense-in-depth, not a reason to ship the tool without an in-process check, and a coding assistant or a browser-automation MCP host will not always be running on a hardened AL2023 box.

## The disclosure and the fix

I filed [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) on 2026-05-12, with a 90-day coordinated-disclosure embargo stated in the issue itself (public release on or after 2026-08-10). The report described the mechanism, the environment dependence, the IMDSv2 caveat, and a suggested fix: allowlist `http`/`https`, resolve the hostname and reject reserved ranges before the request, and offer an env-var opt-in for genuine internal-access needs. I offered to verify any candidate fix before it shipped.

Ten days later, on 2026-05-22, an external community contributor, `@kgarg2468` (not an Anthropic employee), opened PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226), titled *"fix(fetch): block private network URL fetches,"* referencing the issue. The fix does three things:

- validates the URL uses the `http` or `https` scheme,
- resolves the hostname and rejects non-public IPs (loopback, private, link-local, and the metadata-service address),
- follows redirects manually so each redirect target is validated before the next request is made.

That third item is more defensive than my disclosure asked for. Without per-redirect validation, an attacker can host a public URL that 302-redirects to `http://169.254.169.254/...`; a first-request-only check passes and the metadata leak still happens. Validating after each hop closes that bypass. I did not ask for it; the contributor added it anyway, and it is the right call.

## Verifying the fix

On 2026-05-22, the same day the PR went up, I re-ran the exact demo that had exfiltrated the credentials, this time against the fix branch (`kgarg/harden-fetch-ssrf`). Same request, different answer:

```
Fetching private or non-public IP addresses is not allowed
```

The refusal happens at the validation layer, before any network attempt. Because the IP-class check runs before the socket opens, the refusal is observable without a reachable metadata service, which is what let me reproduce it later in a sealed container that never touched EC2.

I did not want to rest a claim on one hand-run demo, so on 2026-06-20 I re-verified through a containerized harness (`poc/ssrf/` in the mcp-witness repo). It drives the real `mcp-server-fetch` package over stdio JSON-RPC against a mock IMDS at `169.254.169.254` inside a Docker network and classifies the response. Two states, end to end:

| State | Source | Result |
|---|---|---|
| Disclosed version | `mcp-server-fetch==2025.4.7` | VULNERABLE (fake `AKIA-FAKE` token returned) |
| PR #4226 branch | `git+…@refs/pull/4226/head` | FIX VERIFIED (URL refused) |

The fixed code path is correct, and I have confirmed it twice: on real infrastructure and in a sealed container.

## The part I did not expect

Here is where the story stops being a clean disclosure loop. The fix PR has never merged. As of today, 2026-09-10, PR #4226 is still open. CI is green, 16 of 16 checks passing with 3 skipped. It picked up one external technical-audit review from `@LuuOW` on 2026-06-13, but no approving review from anyone with write access, which the repository requires to merge. GitHub's own summary on the PR states the blocker plainly: "At least 1 approving review is required by reviewers with write access." Last activity was 2026-06-21, so it has been stale for roughly eleven weeks. The barrier is not code, not tests, not review from the community. It is a single approval from someone who can merge.

Issue #4143 was closed as "not planned" on 2026-07-30 by `@localden`, an Anthropic contributor, who consolidated it into an older umbrella issue, #3741. That umbrella was opened 2026-03-27 by an external contributor, has been dormant, and its only comment is hidden as spam.

And the releases kept coming. `mcp-server-fetch` shipped v2026.6.4 on 2026-06-04, the first release cut after my disclosure, then v2026.7.10 on 2026-07-10, then v2026.8.18 on 2026-08-18, the current latest. On 2026-09-10 I read the source of v2026.8.18, the version you install today, directly: no scheme allowlist, no IP-class check, no redirect validation, the same `AsyncClient.get(url)` path I reported. Three releases shipped after the disclosure and none of them carry the fix, for a simple reason: it has never merged. A patch sitting in an open pull request cannot ship.

I want to be measured about what that means, because the facts carry the weight without editorializing. Coordinated-disclosure obligations here are satisfied: the report was received, considered, and closed by a maintainer, and the 90-day embargo was observed before I published any of this. I do not read intent into the routing. Consolidating a specific security report into a dormant umbrella issue looks to me like triage bandwidth and intake mechanics, not a decision that the bug is acceptable, and a maintainer team with finite time still needs a write-access reviewer to spend attention on an externally authored fix. The outcome is still that a verified, low-risk, self-contained fix for a credential-exfiltration primitive in a reference server has sat unmerged for eleven weeks while releases shipped without it. Both of those things are true at once.

## The companion package

I disclosed the identical SSRF class in `mcp-server-http-request` v0.1.0 (community-published by the startup statespace) the same day, by email, since it had no public issue tracker. After thirty days of silence, cofounder Gavin Chan replied on LinkedIn on 2026-06-11: *"That's not an actively maintained package."* I logged it as maintainer-confirmed-unmaintained. This piece is about the reference server.

## Reproduce it yourself

The reproduction is public and does not touch a real cloud account. The harness lives at [`poc/ssrf/`](https://github.com/desledishant10/mcp-witness/tree/main/poc/ssrf) in the mcp-witness repo. It reproduces in about five seconds:

```bash
cd poc/ssrf/
make demo-full     # disclosed version against a mock IMDS: VULNERABLE
make demo-fixed    # PR #4226 branch: FIX VERIFIED
```

`demo-full` runs the disclosed version against the mock IMDS and checks for the fake `AKIA-FAKE` token; `demo-fixed` installs the PR branch and shows the refusal. The harness exits 0 on vulnerable and 1 on fixed, so it works as a regression check and not only as a demo. The scanner, the finding record, and the full disclosure trail are in the same repo.

## What I take from it

The technical lesson is old. Do not trust the URL parameter. Validate the scheme and the resolved IP class in-process, and treat host-level mitigations as one layer and not the boundary. The core check is a scheme allowlist and an IP-class check, and someone already wrote it.

If you run MCP servers on cloud hosts, two things follow. Set IMDSv2 to Required; it is the highest-impact host control here, and it neutralizes the AWS variant of this bug. And do not treat a reference server as safe just because it is a reference server: audit what you enable, and assume a URL-fetching tool will reach any address it is handed unless the package proves otherwise. The scanner, the EC2 runbook, and the reproduction harness are public in [mcp-witness](https://github.com/desledishant10/mcp-witness) if you want to check your own inventory.

The lesson I did not expect to write up is about the shape of the loop. I did the work end to end: found it with a rule I can defend, proved it on real infrastructure, disclosed it honestly with an embargo I kept, and verified the community fix twice. A fix existing is not a fix shipping. A green, verified PR going stale taught me more about how security lands in an open ecosystem than the bug did, which is why I am publishing the whole arc, ending included. The ending is the honest part.

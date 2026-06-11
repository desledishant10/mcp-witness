# Day +30 escalation templates (2026-06-11)

Both 2026-05-12 email-based disclosures (statespace + atrawog) silent through the 2026-06-02 day +21 ping. Today is day +30. Executing the soft-channel-first escalation per each disclosure record.

## atrawog (`mcp-streamablehttp-proxy` + `mcp-fetch-streamablehttp-server`)

GitHub profile: https://github.com/atrawog (Andreas Trawoeger, 105 public repos, active)
Blog: atrawog.org
Twitter: [@atrawog](https://twitter.com/atrawog)

Three soft channels to try today, in order of preference:

### Channel 1 — Twitter DM to @atrawog (lowest-friction)

Visit https://twitter.com/atrawog. If DMs are open, send:

```
Hi Andreas — Dishant Desle here. I sent a coordinated security disclosure
to atrawog@gmail.com on 2026-05-12 about mcp-streamablehttp-proxy and
mcp-fetch-streamablehttp-server, with a day +21 follow-up on 2026-06-02.
Just checking the original mail reached you (sometimes security mail
ends up in spam). Embargo runs to 2026-08-10; happy to coordinate
timeline / discuss the suggested fix shape (TrustedHostMiddleware +
Origin allowlist) whenever works for you. No urgency, just confirming
visibility.

Thanks,
Dishant
github.com/desledishant10/mcp-witness
```

### Channel 2 — Check atrawog.org for a contact form

Visit https://atrawog.org. If there's a contact form, send a similar short note. If not, skip this channel.

### Channel 3 — Third reply on the existing email thread

If the Twitter DM bounces (DMs closed) and atrawog.org has no contact form, send a brief third email on the existing thread:

```
Hi Andreas,

Day +30 from the original disclosure today. Quick note that I've
attempted to reach you via Twitter (@atrawog) and atrawog.org in
case email's been silent for spam/inbox reasons.

The disclosure record at github.com/desledishant10/mcp-witness/blob/main/disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md
remains in 'awaiting maintainer ack' state. Embargo runs to 2026-08-10.

If I haven't heard from you by day +45 (2026-06-26), I'll file a
non-exploitative pointer issue on atrawog/mcp-oauth-gateway just so the
issue thread reflects there's an active disclosure. No PoC details in
that issue; full disclosure stays embargoed.

Happy to switch to any channel that works better for you.

Thanks,
Dishant
```

### Held back for day +45 (2026-06-26) if still silent — DO NOT FILE NOW

Public GitHub issue on `atrawog/mcp-oauth-gateway`:

> **Title:** Awaiting acknowledgement on coordinated security disclosure sent 2026-05-12
>
> **Body:**
>
> Filing this as a non-exploitative pointer since the email channel has been silent for 45 days.
>
> A coordinated security disclosure was sent to atrawog@gmail.com on 2026-05-12 covering `mcp-streamablehttp-proxy` v0.2.0 and `mcp-fetch-streamablehttp-server` v0.2.0 in this monorepo. A day +21 follow-up was sent on 2026-06-02. Day +30 escalation attempts via Twitter / atrawog.org / a third email also received no response.
>
> **No exploit details in this issue.** The full disclosure record (suggested fix, file references, embargo timeline) is at https://github.com/desledishant10/mcp-witness/blob/main/disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md and remains under embargo until 2026-08-10.
>
> Please reply on this issue or directly to atrawog@gmail.com if the original mail reached you. Happy to switch to any private channel you prefer.

## statespace (`mcp-server-http-request`)

Three soft channels in parallel — no preference order, just send all three:

### Channel 1 — LinkedIn DM to Esteban Safranchik

Search LinkedIn for "Esteban Safranchik statespace" or similar. Send:

```
Hi Esteban —

Dishant Desle here. I sent a coordinated security disclosure to
esteban@statespace.com on 2026-05-12 about mcp-server-http-request
v0.1.0 (an MCP package your team published on PyPI). Followed up on
2026-06-02. Today is day +30 and I want to make sure the original
mail reached you (security mail sometimes ends up in spam).

Quick context: same SSRF class as Anthropic's mcp-server-fetch, which
shipped a fix in modelcontextprotocol/servers PR #4226 that I
independently verified. The fix translates near-verbatim to your
package.

Original email + day +21 follow-up are on the existing thread. Embargo
runs to 2026-08-10. Happy to discuss timeline or remediation on any
channel that works for you.

Thanks,
Dishant Desle
didesle7@gmail.com
github.com/desledishant10/mcp-witness
```

### Channel 2 — LinkedIn DM to Gavin Chan

Same text, just open with "Hi Gavin —" and reference `gavin@statespace.com`.

### Channel 3 — statespace.com contact form

Visit https://statespace.com and look for a Contact / About / Support link. If there's a generic form, send:

```
This is a security disclosure follow-up. I sent a coordinated security
report to esteban@statespace.com and gavin@statespace.com on 2026-05-12
about mcp-server-http-request v0.1.0 on PyPI. A day +21 follow-up was
sent on 2026-06-02. Today is day +30 with no acknowledgement.

I'm reaching out via the generic contact form in case the original
mail was filtered. The full disclosure record (with the suggested fix
shape) is at https://github.com/desledishant10/mcp-witness/blob/main/disclosures/2026-05-12-mcp-fetch-http-request-ssrf.md.

Embargo runs to 2026-08-10. Please reply to didesle7@gmail.com or any
channel that's convenient.

Thanks,
Dishant Desle
```

### Held back for day +45 (2026-06-26) if still silent

GitHub user-profile lookup via @safranchik (the GitHub handle that surfaced for the name Safranchik). If they have any public repos with active recent issues, file a non-exploitative pointer there. Approach as a last resort — the statespace product isn't open-source on GitHub so this is a stretch.

## Recording the escalations

After each message is sent, append a one-line entry to the relevant disclosure file's `## Updates` section so the audit trail reflects the actual channel sequence:

- `disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md`
- `disclosures/2026-05-12-mcp-fetch-http-request-ssrf.md`

Format: `### 2026-06-11 — day +30 escalation: <channel> to <recipient>; <outcome>`.

## Day +45 (2026-06-26) check

Calendar reminder for 2026-06-26: if either disclosure is still silent, execute the held-back public-issue-style escalations above. After day +45 there's nothing further to escalate to short of breaking embargo; day +60 is "final notice" and day +90 is publish-regardless.

## What to do RIGHT NOW (priority order, ~30 min total)

1. **Twitter DM @atrawog** (~5 min) — softest channel, most likely to land
2. **LinkedIn DM Esteban Safranchik** (~5 min) — best single channel for statespace
3. **LinkedIn DM Gavin Chan** (~5 min) — parallel cover
4. **statespace.com contact form** (~10 min, if it exists) — belt and braces
5. **atrawog.org contact form OR third email** (~5 min, last resort if Twitter DM bounces)

Then append the four-or-five `### 2026-06-11 — day +30` entries to the disclosure files and commit.

# Soft escalation: the LinkedIn escape valve pattern

There's a problem with coordinated security disclosure that doesn't show up in any of the standard guides. You email the maintainer. They don't reply. You wait 21 days. You send a polite ping. They don't reply. You wait another 9 days. Now it's day 30 and you have to decide what to do.

The textbook answer is "escalate." The textbook doesn't say how, because what "escalation" means depends on why the maintainer isn't responding, and you don't actually know which case you're in.

There are four cases:

1. They got the mail, are working on a fix, and forgot to acknowledge.
2. They got the mail, are sitting on it for non-technical reasons, and are hoping you forget.
3. They didn't get the mail. Spam, filtering, full inbox.
4. They got the mail, but the project is no longer actively maintained, and they don't want to say so publicly.

Case 4 is the one I think most disclosure work underestimates. A maintainer who has moved on from a project and isn't sure what to do about a security disclosure on it has every incentive to do nothing. Acknowledging the report obligates them to fix or yank. Saying "this is unmaintained" feels like an admission they don't want on the public record. Silence is the path of least resistance.

The pattern I'll describe here is for case 4. It's specifically for the situation where you've been silent through day 30 on an email-only channel and you suspect the project might be unmaintained but you can't tell. The pattern's name is "the escape valve." The point of it is to give the maintainer a face-saving way to close the loop.

## The setup

On 2026-05-12 I filed a coordinated disclosure with statespace for a SSRF in their `mcp-server-http-request` package. Same vulnerability class as the one I'd disclosed against Anthropic's `mcp-server-fetch` the same day. Email to `esteban@statespace.com` and `gavin@statespace.com`, both addresses listed as PyPI maintainers in the package METADATA.

Day +21 ping on 2026-06-02. Silent.

Day +30 on 2026-06-11. I checked the basics first. `statespace.com` didn't load when I visited it. The cofounders' LinkedIn profiles list statespace as their company, but the domain didn't resolve. That's a strong tell for case 4. The company might be wound down. But I had no way to confirm without asking, and asking by email wasn't going to get a different result than the prior 30 days of asking by email had.

## The escape valve

I sent both cofounders a LinkedIn DM. Same structure for each. Here's the verbatim message to Esteban Safranchik:

> Hi Esteban,
>
> Dishant Desle here. I sent a coordinated security disclosure to esteban@statespace.com on 2026-05-12 about mcp-server-http-request v0.1.0 (an MCP package your team published on PyPI). Followed up on 2026-06-02. Today is day +30 and I want to make sure the original mail reached you (security mail sometimes ends up in spam).
>
> Quick context: same SSRF class as Anthropic's mcp-server-fetch, which shipped a fix in modelcontextprotocol/servers PR #4226 that I independently verified. The fix translates near-verbatim to your package.
>
> Original email + day +21 follow-up are on the existing thread. Embargo runs to 2026-08-10. Happy to discuss timeline or remediation on any channel that works for you.

That message is the textbook version. It's polite, it includes the technical context, it invites a reply.

It also has no escape valve in it. If statespace is wound down, this message gives Gavin or Esteban no easy way to say so. The implied request is "please acknowledge and remediate." The implied alternative is "stay silent and look bad in the eventual public writeup."

What I'd do differently next time is add this paragraph:

> If statespace as a company has wound down and the package is no longer actively maintained, that's completely fine. Just let me know and I'll note that in the public writeup. The goal is to get the security record straight, not to pressure you for a fix on a project you've moved on from.

That framing reverses the default. Silence is no longer the path of least resistance. Confirming "this is unmaintained" is now a one-line reply that costs the maintainer nothing socially and puts their position on the public record on their own terms.

## What happened

Within hours of the LinkedIn DM, Gavin Chan replied:

> Hey thanks for reaching out. That's not an actively maintained package.

That's case 4 confirmed. The thirty days of email silence were silence not because the report was being ignored or worked on, but because the project was dead and nobody wanted to say it in writing.

Note what Gavin's reply doesn't have. No acknowledgement of the vulnerability. No fix timeline. No apology. Just confirmation of the operating fact. That's exactly what I needed. The disclosure outcome can now be recorded as "maintainer-confirmed-unmaintained" instead of "silent through embargo," which is a meaningfully different category for the public record.

I sent a yank-ask follow-up to Gavin's reply, asking whether he'd be willing to deprecate or yank the PyPI package. That's the natural next step on a confirmed-unmaintained track. The escalation phase is closed regardless of his answer on the yank.

## Why this works structurally

Three things made the escape-valve framing land.

First, the channel. LinkedIn DM is a peer-to-peer professional medium. It's not the same emotional register as `security@`. The maintainer doesn't feel like they're being processed by a disclosure pipeline. They feel like they're being asked a question by another human in their field.

Second, the explicit option to confirm-unmaintained. By naming the case-4 scenario in the message, I removed the social cost of admitting it. The maintainer doesn't have to spontaneously volunteer "actually this is dead." They just have to confirm the hypothesis the messenger already named.

Third, the public-record framing. "I'll include that in the public writeup" makes the confirmation valuable to the maintainer. Their position is now on the record on their terms instead of as a callout in the silent column. That's an incentive aligned with theirs, not against theirs.

## When not to use this

This pattern works for case 4. It's wrong for case 2.

If the project is actively maintained by a company with a security-sensitive customer base, the soft-escape framing is the wrong escalation. They have legal and contractual reasons to respond on the formal channel. Treating that situation like a small-team peer interaction signals that you don't understand the disclosure norms they operate under, which weakens your position rather than strengthens it. For those cases the right day +30 escalation is the company's bug-bounty platform, their `security@` alias if not already tried, or in the worst case a coordinated-disclosure broker.

The escape valve is specifically for cases where the maintainer is a person, not a company, and where you have circumstantial evidence the project might be inactive. The dead-domain signal in the statespace case (statespace.com not resolving on day 30) is the kind of signal that pushes you toward case 4 rather than case 2.

## The parallel atrawog case

Earlier the same day I tried a similar escalation against the other silent disclosure on the day +30 schedule. atrawog, who maintains `mcp-streamablehttp-proxy` and `mcp-fetch-streamablehttp-server`. Different shape. No LinkedIn I could find. Twitter handle existed but the user had no Twitter account themselves. The blog `atrawog.org` didn't resolve when I checked it. The only available soft channel was a third email on the existing thread, which I sent. Still silent.

That case stays in "case unknown" through day +30. The escape-valve framing didn't have a delivery surface. Day +45 will be a non-exploitative pointer issue on the upstream GitHub repo, which is a harder escalation that puts the disclosure on a public record without requiring the maintainer to confirm anything. The contrast makes the point: the escape valve is a tactic that requires a soft channel to exist. When no soft channel exists, you fall back to the harder escalations.

## What this generalizes to

The escape valve isn't really about LinkedIn or about unmaintained projects. It's about removing social cost from the response you actually need.

Most coordinated-disclosure pings ask for an acknowledgment that obligates the maintainer to do work. If you can find a smaller response that gives you the information you need without obligating them, you reduce the cost of replying, which raises the probability of reply.

For unmaintained projects, the smaller response is "this is unmaintained." For projects with a slow internal process, the smaller response might be "we have it, working through internal review, will reply by date X." For projects where you're not sure who owns it, the smaller response might be "I'm not the right contact, try Y." Each of these is a lower-cost reply than "we accept the disclosure and will fix by date Z."

Naming the smaller response in the message is the move. Don't make the maintainer guess what minimum interaction will satisfy you. Tell them.

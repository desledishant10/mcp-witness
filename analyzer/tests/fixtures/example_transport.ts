// Deliberately-vulnerable TS MCP transport fixture for the S-014 file-level rule.
// Not runnable; exercises the transport Origin/Host checks. Each vulnerable
// case has a safe counterpart so false positives are caught.
import express from "express";
import cors from "cors";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

// VULNERABLE (MCP-S-014): transport with no DNS-rebinding protection.
export function unsafeTransport() {
  return new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
}

// SAFE: DNS-rebinding protection enabled on this instance.
export function safeTransport() {
  return new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableDnsRebindingProtection: true,
    allowedHosts: ["127.0.0.1:3000"],
    allowedOrigins: ["http://localhost:3000"],
  });
}

// VULNERABLE (MCP-S-014): wildcard CORS with credentials.
export function setupCors(app: express.Express) {
  app.use(cors({ origin: "*", credentials: true }));
}

// SAFE: explicit allowlisted origin.
export function setupCorsSafe(app: express.Express) {
  app.use(cors({ origin: "http://localhost:3000", credentials: true }));
}

// VULNERABLE (MCP-S-014): binds all interfaces, no Origin/Host validation here.
export function listen(app: express.Express) {
  app.listen(3000, "0.0.0.0");
}

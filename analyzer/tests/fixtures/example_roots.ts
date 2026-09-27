// Deliberately-vulnerable TS MCP roots fixture for the S-012 rule.
// Declares the roots capability but never consults it: the declared
// filesystem-containment guarantee is not enforced.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

export const server = new Server(
  { name: "demo", version: "1.0.0" },
  { capabilities: { roots: {}, tools: {} } },
);

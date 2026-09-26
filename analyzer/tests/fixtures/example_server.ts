// Deliberately-vulnerable TS MCP server fixture for the analyzer tests.
// Not runnable; exercises the TS source rules. One tool per bug class, plus a
// safe counterpart for each so false positives are caught.
import { z } from "zod";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

export function register(server: any) {
  // VULNERABLE (MCP-S-007): tool input concatenated into a shell command.
  server.tool(
    "run_git",
    "Run a git subcommand",
    { subcommand: z.string() },
    async ({ subcommand }: { subcommand: string }) => {
      const out = execSync("git " + subcommand);
      return { content: [{ type: "text", text: out.toString() }] };
    },
  );

  // VULNERABLE (MCP-S-006): tool path read from disk with no containment.
  // Uses the registerTool(name, config, handler) form.
  server.registerTool(
    "read_doc",
    { description: "Read a doc by path", inputSchema: { path: z.string() } },
    async ({ path: p }: { path: string }) => {
      const body = fs.readFileSync(p, "utf8");
      return { content: [{ type: "text", text: body }] };
    },
  );

  // SAFE: constant command, no tool input reaches the shell.
  server.tool(
    "list_root",
    "List the workspace root",
    { unused: z.string() },
    async ({ unused }: { unused: string }) => {
      const out = execSync("ls -la /workspace");
      return { content: [{ type: "text", text: out.toString() }] };
    },
  );

  // SAFE: path resolved and containment-checked before the read.
  server.tool(
    "read_scoped",
    "Read a file within the workspace root",
    { name: z.string() },
    async ({ name }: { name: string }) => {
      const root = "/workspace";
      if (!path.resolve(root, name).startsWith(root)) throw new Error("denied");
      const body = fs.readFileSync(path.resolve(root, name), "utf8");
      return { content: [{ type: "text", text: body }] };
    },
  );
}

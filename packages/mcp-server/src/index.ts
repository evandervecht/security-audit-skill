#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  scanProject,
  scanFile,
  scanLive,
  explainFinding,
  listReferences,
  getReference,
  lookupCvesForCheckpoint,
} from "@security-audit/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Skill root is two levels up from packages/mcp-server/dist/
const SKILL_ROOT = resolve(__dirname, "../../..");

const server = new McpServer({
  name: "security-audit",
  version: "0.1.0",
});

// === Tools ===

server.tool(
  "security_scan",
  "Scan a project directory for security vulnerabilities. Auto-detects languages and frameworks, runs relevant checkpoints, returns structured findings.",
  {
    projectPath: z.string().describe("Absolute path to the project directory to scan"),
  },
  async ({ projectPath }) => {
    const result = await scanProject(resolve(projectPath), SKILL_ROOT);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  },
);

server.tool(
  "check_file",
  "Scan a single file for security vulnerabilities. Runs all checkpoints matching the file's language/extension.",
  {
    filePath: z.string().describe("Absolute path to the file to check"),
  },
  async ({ filePath }) => {
    const findings = await scanFile(resolve(filePath), SKILL_ROOT);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              file: filePath,
              findings,
              count: findings.length,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

server.tool(
  "explain_finding",
  "Get detailed reference documentation for a checkpoint ID, including vulnerable/secure code examples and remediation guidance.",
  {
    checkpointId: z
      .string()
      .describe("The checkpoint ID (e.g., SA-PY-01, SA-JS-06, SA-REACT-01)"),
  },
  async ({ checkpointId }) => {
    const result = explainFinding(SKILL_ROOT, checkpointId);
    if (!result || !result.reference) {
      return {
        content: [
          {
            type: "text" as const,
            text: `No reference documentation found for checkpoint ${checkpointId}`,
          },
        ],
      };
    }
    return {
      content: [
        {
          type: "text" as const,
          text: result.reference,
        },
      ],
    };
  },
);

server.tool(
  "security_scan_live",
  "Scan a live URL for security misconfigurations — checks security headers (HSTS, CSP), TLS version, CORS policy, cookie flags, open redirects, and verbose error pages.",
  {
    url: z.string().describe("URL to scan (e.g., https://example.com)"),
  },
  async ({ url }) => {
    const result = await scanLive(url);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  },
);

server.tool(
  "lookup_cves",
  "Look up known CVEs associated with a checkpoint ID by querying the NVD API. Returns matching CVEs with CVSS scores and descriptions.",
  {
    checkpointId: z
      .string()
      .describe("The checkpoint ID to look up CVEs for (e.g., SA-PY-01, SA-JAVA-03)"),
  },
  async ({ checkpointId }) => {
    const cves = await lookupCvesForCheckpoint(checkpointId);
    return {
      content: [
        {
          type: "text" as const,
          text:
            cves.length > 0
              ? JSON.stringify(cves, null, 2)
              : `No CVEs found for checkpoint ${checkpointId} (may not have a CWE mapping or NVD returned no results)`,
        },
      ],
    };
  },
);

server.tool(
  "dependency_sandbox",
  "Install a package in an isolated Docker container and monitor for suspicious behavior (network calls to non-registry hosts, unexpected file writes, process spawning). Requires Docker.",
  {
    ecosystem: z.enum(["npm", "pip", "go", "rust", "dotnet"]).describe("Package ecosystem"),
    package: z.string().describe("Package name with optional version (e.g., lodash@4.17.21, requests==2.31.0, github.com/gin-gonic/gin, serde, Newtonsoft.Json)"),
  },
  async ({ ecosystem, package: pkg }) => {
    const { execFileSync } = await import("node:child_process");
    const scriptPath = resolve(SKILL_ROOT, "scripts/dependency-sandbox.sh");

    // Validate package name — strict allowlist (no shell metacharacters)
    if (!/^[a-zA-Z0-9@._\-/=:^~]+$/.test(pkg)) {
      return {
        content: [{ type: "text" as const, text: `Invalid package name: contains disallowed characters` }],
      };
    }

    try {
      // Use execFileSync with argument array to prevent shell injection
      const output = execFileSync("bash", [scriptPath, ecosystem, pkg], {
        timeout: 120000,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      return {
        content: [{ type: "text" as const, text: output }],
      };
    } catch (e: any) {
      return {
        content: [
          {
            type: "text" as const,
            text: e.stdout || e.stderr || `Sandbox failed: ${e.message}`,
          },
        ],
      };
    }
  },
);

// === Resources ===

server.resource(
  "references",
  "security-audit://references",
  async (uri) => {
    const refs = listReferences(SKILL_ROOT);
    return {
      contents: [
        {
          uri: uri.href,
          mimeType: "application/json",
          text: JSON.stringify(refs, null, 2),
        },
      ],
    };
  },
);

// === Prompts ===

server.prompt(
  "security_audit",
  "Run a comprehensive security audit on a project",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project directory"),
  },
  ({ projectPath }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Run a comprehensive security audit on the project at ${projectPath}.

1. First, use the security_scan tool to detect languages and run all relevant checkpoints.
2. Review the findings, prioritizing critical and high severity issues.
3. For each high-severity finding, use explain_finding to get the reference documentation.
4. Provide a summary report with:
   - Detected stack (languages/frameworks)
   - Total findings by severity
   - Top 5 most critical findings with remediation steps
   - Overall security posture assessment`,
        },
      },
    ],
  }),
);

server.prompt(
  "quick_check",
  "Quick security check on a single file",
  {
    filePath: z.string().describe("Absolute path to the file to check"),
  },
  ({ filePath }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Quick security check on ${filePath}. Use check_file to scan it, then explain any findings using explain_finding.`,
        },
      },
    ],
  }),
);

// === Start ===

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);

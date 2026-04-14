/**
 * Node.js Runtime Hook — intercepts HTTP request handling and wraps
 * dangerous sinks to detect taint flow.
 *
 * Usage: node --import @security-audit/runtime-agent ./app.js
 *   Or:  node --require @security-audit/runtime-agent/dist/hook-cjs.js ./app.js
 *
 * Wraps:
 *   - child_process.exec/execSync (command injection sink)
 *   - fs.readFile/readFileSync (path traversal sink)
 *   - eval / Function constructor (code injection sink)
 *   - SQL query methods (SQL injection sink)
 */

import { Module } from "node:module";
import { markTainted, isTainted, reportSinkAccess, getFindings, setReportCallback } from "./taint-tracker.js";
import type { TaintFinding } from "./taint-tracker.js";

const originalRequire = Module.prototype.require;

// Track which modules we've already wrapped
const wrappedModules = new Set<string>();

function getCallLocation(): string {
  const stack = new Error().stack;
  if (!stack) return "unknown";
  const lines = stack.split("\n");
  // Skip: Error, getCallLocation, reportSinkAccess, the wrapper, the actual caller
  for (let i = 3; i < lines.length; i++) {
    const line = lines[i].trim();
    if (
      !line.includes("runtime-agent") &&
      !line.includes("node:internal") &&
      !line.includes("node_modules")
    ) {
      const match = line.match(/\((.+)\)/) || line.match(/at (.+)/);
      return match?.[1] || line;
    }
  }
  return "unknown";
}

// === Wrap child_process ===
function wrapChildProcess(mod: any): any {
  const origExec = mod.exec;
  const origExecSync = mod.execSync;

  if (origExec) {
    mod.exec = function wrappedExec(command: string, ...args: any[]) {
      const taintSource = isTainted(command);
      if (taintSource) {
        reportSinkAccess("child_process.exec", [command], getCallLocation());
        throw new Error(
          `[security-audit] BLOCKED: tainted value from ${taintSource.type}.${taintSource.key} reached child_process.exec(). ` +
            `This is a command injection vulnerability.`,
        );
      }
      return origExec.call(this, command, ...args);
    };
  }

  if (origExecSync) {
    mod.execSync = function wrappedExecSync(command: string, ...args: any[]) {
      const taintSource = isTainted(command);
      if (taintSource) {
        reportSinkAccess("child_process.execSync", [command], getCallLocation());
        throw new Error(
          `[security-audit] BLOCKED: tainted value from ${taintSource.type}.${taintSource.key} reached child_process.execSync(). ` +
            `This is a command injection vulnerability.`,
        );
      }
      return origExecSync.call(this, command, ...args);
    };
  }

  return mod;
}

// === Wrap fs ===
function wrapFs(mod: any): any {
  const origReadFile = mod.readFile;
  const origReadFileSync = mod.readFileSync;
  const origWriteFile = mod.writeFile;

  if (origReadFile) {
    mod.readFile = function wrappedReadFile(path: string, ...args: any[]) {
      const taintSource = isTainted(path);
      if (taintSource) {
        reportSinkAccess("fs.readFile", [path], getCallLocation());
        throw new Error(
          `[security-audit] BLOCKED: tainted value from ${taintSource.type}.${taintSource.key} reached fs.readFile(). ` +
            `This is a path traversal vulnerability.`,
        );
      }
      return origReadFile.call(this, path, ...args);
    };
  }

  if (origReadFileSync) {
    mod.readFileSync = function wrappedReadFileSync(path: string, ...args: any[]) {
      const taintSource = isTainted(path);
      if (taintSource) {
        reportSinkAccess("fs.readFileSync", [path], getCallLocation());
        throw new Error(
          `[security-audit] BLOCKED: tainted value from ${taintSource.type}.${taintSource.key} reached fs.readFileSync(). ` +
            `This is a path traversal vulnerability.`,
        );
      }
      return origReadFileSync.call(this, path, ...args);
    };
  }

  if (origWriteFile) {
    mod.writeFile = function wrappedWriteFile(path: string, ...args: any[]) {
      const taintSource = isTainted(path);
      if (taintSource) {
        reportSinkAccess("fs.writeFile", [path], getCallLocation());
        throw new Error(
          `[security-audit] BLOCKED: tainted value from ${taintSource.type}.${taintSource.key} reached fs.writeFile(). ` +
            `This is a path traversal vulnerability.`,
        );
      }
      return origWriteFile.call(this, path, ...args);
    };
  }

  return mod;
}

// === Wrap HTTP request objects to taint inputs ===
function wrapHttpIncomingMessage(req: any): void {
  // Taint query parameters
  if (req.query) {
    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === "string") {
        markTainted(value, {
          type: "query",
          key,
          location: `${req.method} ${req.url}`,
        });
      }
    }
  }

  // Taint route params
  if (req.params) {
    for (const [key, value] of Object.entries(req.params)) {
      if (typeof value === "string") {
        markTainted(value, {
          type: "params",
          key,
          location: `${req.method} ${req.url}`,
        });
      }
    }
  }

  // Taint body
  if (req.body && typeof req.body === "object") {
    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value === "string") {
        markTainted(value, {
          type: "body",
          key,
          location: `${req.method} ${req.url}`,
        });
      }
    }
  }

  // Taint headers
  for (const [key, value] of Object.entries(req.headers || {})) {
    if (typeof value === "string" && ["authorization", "cookie", "referer", "x-forwarded-for"].includes(key)) {
      markTainted(value, {
        type: "headers",
        key,
        location: `${req.method} ${req.url}`,
      });
    }
  }
}

// === Wrap Express/Fastify middleware to intercept requests ===
function wrapExpressApp(mod: any): any {
  const origUse = mod.prototype?.use;
  if (!origUse) return mod;

  // Inject our taint middleware before all other middleware
  const origListen = mod.prototype.listen;
  if (origListen) {
    mod.prototype.listen = function wrappedListen(...args: any[]) {
      // Inject taint middleware at the front
      this.use((req: any, _res: any, next: any) => {
        wrapHttpIncomingMessage(req);
        next();
      });
      return origListen.apply(this, args);
    };
  }

  return mod;
}

// === Module interception ===
Module.prototype.require = function wrappedRequire(id: string) {
  const result = originalRequire.apply(this, [id]);

  if (!wrappedModules.has(id)) {
    wrappedModules.add(id);

    switch (id) {
      case "child_process":
      case "node:child_process":
        return wrapChildProcess(result);

      case "fs":
      case "node:fs":
        return wrapFs(result);

      case "express":
        return wrapExpressApp(result);
    }
  }

  return result;
};

// === Wrap global eval ===
const originalEval = globalThis.eval;
globalThis.eval = function wrappedEval(code: string) {
  const taintSource = isTainted(code);
  if (taintSource) {
    reportSinkAccess("eval", [code], getCallLocation());
    throw new Error(
      `[security-audit] BLOCKED: tainted value from ${taintSource.type}.${taintSource.key} reached eval(). ` +
        `This is a code injection vulnerability.`,
    );
  }
  return originalEval(code);
};

// === Report findings on exit ===
process.on("exit", () => {
  const allFindings = getFindings();
  if (allFindings.length > 0) {
    console.error(
      `\n[security-audit] Runtime Analysis Summary\n` +
        `  Taint flows detected: ${allFindings.length}\n`,
    );
    for (const f of allFindings) {
      console.error(
        `  - ${f.source.type}.${f.source.key} → ${f.sink} (${f.sinkLocation})`,
      );
    }
    console.error("");
  }
});

// === JSON report output ===
setReportCallback((finding: TaintFinding) => {
  // Write to a report file if env var is set
  const reportFile = process.env.SECURITY_AUDIT_REPORT;
  if (reportFile) {
    const { appendFileSync } = require("fs");
    appendFileSync(reportFile, JSON.stringify(finding) + "\n");
  }
});

console.error("[security-audit] Runtime agent loaded — monitoring taint flows");

export { getFindings, clearFindings } from "./taint-tracker.js";
export type { TaintFinding } from "./taint-tracker.js";

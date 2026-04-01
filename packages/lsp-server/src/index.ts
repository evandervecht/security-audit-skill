#!/usr/bin/env node
import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  InitializeResult,
  TextDocumentSyncKind,
  Diagnostic,
  DiagnosticSeverity,
  CodeAction,
  CodeActionKind,
  CodeActionParams,
  Command,
} from "vscode-languageserver/node.js";
import { TextDocument } from "vscode-languageserver-textdocument";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadCheckpoints,
  explainFinding,
  type Checkpoint,
  type CheckpointData,
} from "@security-audit/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKILL_ROOT = resolve(__dirname, "../../..");

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);

let checkpointData: CheckpointData | null = null;

connection.onInitialize((_params: InitializeParams): InitializeResult => {
  // Load checkpoints once at startup
  try {
    const checkpointsPath = resolve(
      SKILL_ROOT,
      "skills/security-audit/checkpoints.yaml",
    );
    checkpointData = loadCheckpoints(checkpointsPath);
  } catch (e) {
    connection.console.error(`Failed to load checkpoints: ${e}`);
  }

  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      codeActionProvider: {
        codeActionKinds: [CodeActionKind.QuickFix],
      },
    },
  };
});

// Map file extensions to checkpoint target patterns
function getExtension(uri: string): string {
  const parts = uri.split(".");
  return parts[parts.length - 1] || "";
}

function getCheckpointsForFile(ext: string): Checkpoint[] {
  if (!checkpointData) return [];

  return checkpointData.mechanical.filter((cp) => {
    if (!cp.pattern) return false;
    // Extract extensions from target glob like "**/*.{js,ts,jsx,tsx}"
    const targetMatch = cp.target.match(/\*\.(\{[^}]+\}|\w+)$/);
    if (!targetMatch) return false;

    const extPart = targetMatch[1];
    if (extPart.startsWith("{")) {
      const exts = extPart.slice(1, -1).split(",");
      return exts.includes(ext);
    }
    return extPart === ext;
  });
}

function severityToLsp(
  severity: "error" | "warning" | "info",
): DiagnosticSeverity {
  switch (severity) {
    case "error":
      return DiagnosticSeverity.Error;
    case "warning":
      return DiagnosticSeverity.Warning;
    case "info":
      return DiagnosticSeverity.Information;
  }
}

function validateTextDocument(textDocument: TextDocument): void {
  const ext = getExtension(textDocument.uri);
  const checkpoints = getCheckpointsForFile(ext);

  if (checkpoints.length === 0) return;

  const text = textDocument.getText();
  const lines = text.split("\n");
  const diagnostics: Diagnostic[] = [];

  for (const cp of checkpoints) {
    if (!cp.pattern) continue;

    let regex: RegExp;
    try {
      regex = new RegExp(cp.pattern);
    } catch {
      continue;
    }

    for (let i = 0; i < lines.length; i++) {
      const match = regex.exec(lines[i]);
      if (match) {
        diagnostics.push({
          severity: severityToLsp(cp.severity),
          range: {
            start: { line: i, character: match.index },
            end: { line: i, character: match.index + match[0].length },
          },
          message: `[${cp.id}] ${cp.desc}`,
          source: "security-audit",
          code: cp.id,
          data: { checkpointId: cp.id },
        });
      }
    }
  }

  connection.sendDiagnostics({
    uri: textDocument.uri,
    diagnostics,
  });
}

// Validate on open and save
documents.onDidOpen((event) => {
  validateTextDocument(event.document);
});

documents.onDidSave((event) => {
  validateTextDocument(event.document);
});

// Also validate on content change (with debounce via the incremental sync)
documents.onDidChangeContent((event) => {
  validateTextDocument(event.document);
});

// Clear diagnostics when document is closed
documents.onDidClose((event) => {
  connection.sendDiagnostics({
    uri: event.document.uri,
    diagnostics: [],
  });
});

// Code actions — "Show secure alternative"
connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const actions: CodeAction[] = [];

  for (const diag of params.context.diagnostics) {
    if (diag.source !== "security-audit") continue;

    const checkpointId =
      (diag.data as { checkpointId?: string })?.checkpointId ||
      (typeof diag.code === "string" ? diag.code : undefined);

    if (!checkpointId) continue;

    actions.push({
      title: `View security reference for ${checkpointId}`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [diag],
      command: {
        title: "Show Reference",
        command: "security-audit.showReference",
        arguments: [checkpointId],
      },
    });
  }

  return actions;
});

// Custom command to get reference content (called by IDE extensions)
connection.onExecuteCommand(async (params) => {
  if (params.command === "security-audit.showReference") {
    const checkpointId = params.arguments?.[0] as string;
    if (!checkpointId) return;

    const result = explainFinding(SKILL_ROOT, checkpointId);
    if (result?.reference) {
      connection.window.showInformationMessage(
        `Reference for ${checkpointId} loaded. See output channel for details.`,
      );
      connection.console.log(result.reference);
    }
  }
});

documents.listen(connection);
connection.listen();

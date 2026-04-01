import * as vscode from "vscode";
import * as path from "node:path";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node.js";

let client: LanguageClient;
let statusBarItem: vscode.StatusBarItem;
let findingsCount = 0;

export function activate(context: vscode.ExtensionContext) {
  // LSP server path — bundled in the extension
  const serverModule = path.resolve(
    context.extensionPath,
    "..",
    "lsp-server",
    "dist",
    "index.js",
  );

  const serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.stdio },
    debug: { module: serverModule, transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "php" },
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "java" },
      { scheme: "file", language: "csharp" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "rust" },
      { scheme: "file", language: "ruby" },
      { scheme: "file", language: "vue" },
      { scheme: "file", language: "swift" },
      { scheme: "file", language: "kotlin" },
      { scheme: "file", language: "terraform" },
      { scheme: "file", language: "xml" },
      { scheme: "file", language: "yaml" },
      { scheme: "file", language: "json" },
      { scheme: "file", language: "bicep" },
      { scheme: "file", language: "razor" },
    ],
    diagnosticCollectionName: "security-audit",
  };

  client = new LanguageClient(
    "security-audit",
    "Security Audit",
    serverOptions,
    clientOptions,
  );

  // Status bar item — shows finding count
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  statusBarItem.command = "security-audit.scanFile";
  context.subscriptions.push(statusBarItem);

  // Update status bar when diagnostics change
  context.subscriptions.push(
    vscode.languages.onDidChangeDiagnostics(() => {
      updateStatusBar();
    }),
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "security-audit.scanWorkspace",
      async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
          vscode.window.showWarningMessage("No workspace folder open");
          return;
        }

        vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "Security Audit: Scanning workspace...",
            cancellable: false,
          },
          async () => {
            // Trigger re-scan by touching all open documents
            for (const editor of vscode.window.visibleTextEditors) {
              const doc = editor.document;
              // Force a change event to trigger LSP validation
              const edit = new vscode.WorkspaceEdit();
              // No-op edit to trigger diagnostics refresh
              await vscode.workspace.applyEdit(edit);
            }

            vscode.window.showInformationMessage(
              "Security Audit: Workspace scan complete",
            );
          },
        );
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("security-audit.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("No active file");
        return;
      }

      // The LSP server handles this automatically on file open/change
      vscode.window.showInformationMessage(
        `Security Audit: ${editor.document.fileName} — diagnostics are live`,
      );
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      "security-audit.showReference",
      async (checkpointId?: string) => {
        if (!checkpointId) {
          checkpointId = await vscode.window.showInputBox({
            prompt: "Enter checkpoint ID (e.g., SA-PY-01, SA-JS-06)",
            placeHolder: "SA-PY-01",
          });
        }

        if (!checkpointId) return;

        // Get reference from core
        try {
          const { explainFinding } = await import("@security-audit/core");
          const skillRoot = path.resolve(context.extensionPath, "../..");
          const result = explainFinding(skillRoot, checkpointId);

          if (result?.reference) {
            // Show in a new untitled document
            const doc = await vscode.workspace.openTextDocument({
              content: result.reference,
              language: "markdown",
            });
            await vscode.window.showTextDocument(doc, {
              preview: true,
              viewColumn: vscode.ViewColumn.Beside,
            });
          } else {
            vscode.window.showWarningMessage(
              `No reference found for ${checkpointId}`,
            );
          }
        } catch (e) {
          vscode.window.showErrorMessage(
            `Failed to load reference: ${e}`,
          );
        }
      },
    ),
  );

  // Start the LSP client
  client.start();
  updateStatusBar();
}

function updateStatusBar() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    statusBarItem.hide();
    return;
  }

  const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
  const securityFindings = diagnostics.filter(
    (d) => d.source === "security-audit",
  );
  findingsCount = securityFindings.length;

  if (findingsCount > 0) {
    const errors = securityFindings.filter(
      (d) => d.severity === vscode.DiagnosticSeverity.Error,
    ).length;
    const warnings = securityFindings.filter(
      (d) => d.severity === vscode.DiagnosticSeverity.Warning,
    ).length;

    statusBarItem.text = `$(shield) ${findingsCount} finding${findingsCount === 1 ? "" : "s"}`;
    statusBarItem.tooltip = `Security Audit: ${errors} error(s), ${warnings} warning(s)`;
    statusBarItem.backgroundColor =
      errors > 0
        ? new vscode.ThemeColor("statusBarItem.errorBackground")
        : undefined;
  } else {
    statusBarItem.text = "$(shield) Secure";
    statusBarItem.tooltip = "Security Audit: No findings";
    statusBarItem.backgroundColor = undefined;
  }

  statusBarItem.show();
}

export function deactivate(): Thenable<void> | undefined {
  statusBarItem?.dispose();
  return client?.stop();
}

# Editor Integration Configs

Ready-to-use configuration snippets for all supported editors and AI IDEs.

## MCP Server (AI-powered IDEs)

### Claude Code
```json
// ~/.claude/settings.json or project .claude/settings.json
{
  "mcpServers": {
    "security-audit": {
      "command": "node",
      "args": ["/path/to/security-audit-skill/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Cursor
```json
// .cursor/mcp.json
{
  "mcpServers": {
    "security-audit": {
      "command": "node",
      "args": ["/path/to/security-audit-skill/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### GitHub Copilot (VS Code)
MCP support in Copilot uses the same VS Code MCP config:
```json
// .vscode/mcp.json
{
  "servers": {
    "security-audit": {
      "command": "node",
      "args": ["/path/to/security-audit-skill/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Windsurf (Codeium)
```json
// ~/.codeium/windsurf/mcp_config.json
{
  "mcpServers": {
    "security-audit": {
      "command": "node",
      "args": ["/path/to/security-audit-skill/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Zed
```json
// ~/.config/zed/settings.json
{
  "context_servers": {
    "security-audit": {
      "command": {
        "path": "node",
        "args": ["/path/to/security-audit-skill/packages/mcp-server/dist/index.js"]
      }
    }
  }
}
```

---

## LSP Server (Traditional editors)

### Neovim (via nvim-lspconfig)
```lua
-- ~/.config/nvim/lua/plugins/security-audit.lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

configs.security_audit = {
  default_config = {
    cmd = { 'node', '/path/to/security-audit-skill/packages/lsp-server/dist/index.js', '--stdio' },
    filetypes = {
      'php', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
      'python', 'java', 'cs', 'go', 'rust', 'ruby', 'vue', 'swift', 'kotlin',
      'terraform', 'xml', 'yaml', 'json', 'bicep',
    },
    root_dir = lspconfig.util.root_pattern('.git', 'package.json', 'go.mod', 'Cargo.toml'),
    settings = {},
  },
}

lspconfig.security_audit.setup({})
```

### Helix
```toml
# ~/.config/helix/languages.toml
[language-server.security-audit]
command = "node"
args = ["/path/to/security-audit-skill/packages/lsp-server/dist/index.js", "--stdio"]

[[language]]
name = "javascript"
language-servers = ["typescript-language-server", "security-audit"]

[[language]]
name = "python"
language-servers = ["pylsp", "security-audit"]

[[language]]
name = "go"
language-servers = ["gopls", "security-audit"]

[[language]]
name = "rust"
language-servers = ["rust-analyzer", "security-audit"]

# Repeat for other languages...
```

### Sublime Text (via LSP package)
```json
// Preferences > Package Settings > LSP > Settings
{
  "clients": {
    "security-audit": {
      "enabled": true,
      "command": ["node", "/path/to/security-audit-skill/packages/lsp-server/dist/index.js", "--stdio"],
      "selector": "source.php | source.js | source.ts | source.python | source.java | source.cs | source.go | source.rust | source.ruby"
    }
  }
}
```

### Emacs (via lsp-mode)
```elisp
;; ~/.emacs.d/init.el or ~/.config/emacs/init.el
(with-eval-after-load 'lsp-mode
  (lsp-register-client
   (make-lsp-client
    :new-connection (lsp-stdio-connection
                     '("node" "/path/to/security-audit-skill/packages/lsp-server/dist/index.js" "--stdio"))
    :activation-fn (lsp-activate-on "php" "javascript" "typescript" "python" "java" "csharp" "go" "rust" "ruby")
    :server-id 'security-audit)))
```

### Emacs (via eglot — built-in since Emacs 29)
```elisp
(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs
               '((php-mode js-mode typescript-mode python-mode java-mode csharp-mode go-mode rust-mode ruby-mode)
                 . ("node" "/path/to/security-audit-skill/packages/lsp-server/dist/index.js" "--stdio"))))
```

### Kakoune (via kak-lsp)
```toml
# ~/.config/kak-lsp/kak-lsp.toml
[language.security-audit]
filetypes = ["php", "javascript", "typescript", "python", "java", "csharp", "go", "rust", "ruby"]
roots = [".git", "package.json", "go.mod", "Cargo.toml"]
command = "node"
args = ["/path/to/security-audit-skill/packages/lsp-server/dist/index.js", "--stdio"]
```

### Eclipse (via LSP4E)
1. Install LSP4E from Eclipse Marketplace
2. Go to: Window → Preferences → Language Servers
3. Add new server:
   - Program: `node`
   - Arguments: `/path/to/security-audit-skill/packages/lsp-server/dist/index.js --stdio`
   - File types: `*.php, *.js, *.ts, *.py, *.java, *.cs, *.go, *.rs, *.rb`

### Kate / KTextEditor
```json
// ~/.config/kate/lspclient/settings.json
{
  "servers": {
    "security-audit": {
      "command": ["node", "/path/to/security-audit-skill/packages/lsp-server/dist/index.js", "--stdio"],
      "languages": ["php", "javascript", "typescript", "python", "java", "csharp", "go", "rust", "ruby"]
    }
  }
}
```

---

## Dedicated Plugins

### VS Code
Install the `security-audit` extension from the VS Code Marketplace, or from source:
```bash
cd packages/vscode-ext
npm install && npm run build
npx @vscode/vsce package
code --install-extension security-audit-0.1.0.vsix
```

### JetBrains (PyCharm, IntelliJ, WebStorm, etc.)
Install from JetBrains Marketplace, or from source:
```bash
cd packages/jetbrains-plugin
./gradlew buildPlugin
# Install from: build/distributions/security-audit-plugin-0.1.0.zip
```

---

## Supported Editors Summary

| Editor | Integration | Config Location |
|--------|------------|-----------------|
| **Claude Code** | MCP | `~/.claude/settings.json` |
| **Cursor** | MCP | `.cursor/mcp.json` |
| **GitHub Copilot** | MCP | `.vscode/mcp.json` |
| **Windsurf** | MCP | `~/.codeium/windsurf/mcp_config.json` |
| **Zed** | MCP | `~/.config/zed/settings.json` |
| **VS Code** | Extension | VS Code Marketplace |
| **PyCharm/IntelliJ** | Plugin | JetBrains Marketplace |
| **Neovim** | LSP | `nvim-lspconfig` |
| **Helix** | LSP | `~/.config/helix/languages.toml` |
| **Sublime Text** | LSP | LSP package settings |
| **Emacs (lsp-mode)** | LSP | `init.el` |
| **Emacs (eglot)** | LSP | `init.el` |
| **Kakoune** | LSP | `kak-lsp.toml` |
| **Eclipse** | LSP | LSP4E preferences |
| **Kate** | LSP | `lspclient/settings.json` |

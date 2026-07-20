# Elixir & Phoenix Security Patterns

Security patterns, common misconfigurations, and detection regexes for Elixir applications and the Phoenix web framework. Phoenix provides strong defaults — HEEx templates auto-escape output, Ecto parameterizes queries, and the generated `:browser` pipeline enables CSRF protection — but developers regularly bypass these safeguards with `raw/1`, interpolated `fragment`/`where` strings, and removed `protect_from_forgery` plugs. Elixir itself exposes runtime metaprogramming (`Code.eval_string`), dynamic atom creation, and shell execution that become RCE or DoS vectors when fed untrusted data. Understanding these patterns is essential for auditing Elixir/Phoenix applications.

---

## Atom Exhaustion (Denial of Service)

### SA-EX-01: String.to_atom / binary_to_atom on User Input

Atoms in the BEAM are never garbage collected and the atom table has a fixed limit (default ~1,048,576). Converting arbitrary user input to atoms with `String.to_atom/1`, `:erlang.binary_to_atom/1,2`, or `List.to_atom/1` lets an attacker create unbounded distinct atoms until the VM crashes.

```elixir
# VULNERABLE: every distinct role string adds a permanent atom
def assign(conn, %{"role" => role}) do
  role_atom = String.to_atom(role)
  do_assign(conn, role_atom)
end

# VULNERABLE: dynamic atom from request header / params
key = :erlang.binary_to_atom(params["key"], :utf8)
```

```elixir
# SAFE: allowlist + to_existing_atom (raises if the atom is unknown)
@allowed ~w(admin editor viewer)

def assign(conn, %{"role" => role}) when role in @allowed do
  role_atom = String.to_existing_atom(role)
  do_assign(conn, role_atom)
end
```

**Detection regex:** `String\.to_atom\s*\(|:erlang\.binary_to_atom\s*\(|List\.to_atom\s*\(`
**Checkpoint:** SA-EX-01
**Severity:** error

---

## Code Injection

### SA-EX-02: Code.eval_string / eval_quoted / EEx.eval_string

`Code.eval_string/1`, `Code.eval_quoted/1`, and `EEx.eval_string/2` compile and execute Elixir at runtime. Any user-controlled fragment becomes remote code execution.

```elixir
# VULNERABLE: arbitrary code execution
def run(conn, %{"expr" => expr}) do
  {result, _binding} = Code.eval_string(expr)
  json(conn, %{result: result})
end

# VULNERABLE: EEx template built from user data
EEx.eval_string("Hello <%= System.cmd(\"id\", []) %> #{user_input}")
```

```elixir
# SAFE: delegate to a dedicated, sandboxed evaluator/parser
def run(conn, %{"expr" => expr}) do
  result = MyApp.SafeMath.evaluate(expr)
  json(conn, %{result: result})
end
```

**Detection regex:** `Code\.eval_string\s*\(|Code\.eval_quoted\s*\(|EEx\.eval_string\s*\(`
**Checkpoint:** SA-EX-02
**Severity:** error

---

## OS Command Injection

### SA-EX-03: System.cmd / :os.cmd with Interpolation

`:os.cmd/1` runs a string through a shell. `System.cmd/3` does not spawn a shell when given an executable plus an argument list, but interpolating user input into the command string — or invoking `sh -c "..."` — reintroduces shell injection.

```elixir
# VULNERABLE: :os.cmd runs a shell string
:os.cmd(~c"ping -c 1 #{host}")

# VULNERABLE: sh -c with an interpolated argument
System.cmd("sh", ["-c", "convert #{file} out.png"])
```

```elixir
# SAFE: executable + explicit arg list, no shell
System.cmd("ping", ["-c", "1", host])
System.cmd("convert", [file, "out.png"])
```

**Detection regex:** `(?:System\.cmd|:os\.cmd)\s*\([^)]*#\{`
**Checkpoint:** SA-EX-03
**Severity:** error

---

## Sensitive Data Disclosure

### SA-EX-04: Secrets in Logger / inspect

Logging secrets via `Logger` or `inspect/1` writes them in plaintext to log files and aggregators. Use `@derive {Inspect, except: [...]}` on structs holding secrets and never log credential fields.

```elixir
# VULNERABLE: secrets land in logs
Logger.info("Login attempt: #{inspect(password)}")
Logger.debug("token=#{inspect(token)} secret=#{inspect(user.secret_key)}")
```

```elixir
# SAFE: log only non-sensitive identifiers
Logger.info("Login attempt for user=#{inspect(user.id)}")
```

**Detection regex:** `(?i)Logger\.\w+\([^)]*(?:password|secret|token|api[_-]?key|private[_-]?key|credential)[^)]*inspect|inspect\([^)]*(?:password|secret_key|api_key|private_key|credential)`
**Checkpoint:** SA-EX-04
**Severity:** warning

---

## SQL Injection (Ecto)

### SA-PHOENIX-01: fragment / where with String Interpolation

Ecto parameterizes queries when you use the query DSL with pinned (`^`) values or `?` placeholders in `fragment/1,2`. Interpolating user input directly into a `fragment` or a `where:` string builds raw SQL and is injectable.

```elixir
# VULNERABLE: interpolation builds raw SQL
from(p in Post, where: fragment("title LIKE '%#{term}%'"))
Repo.all(from p in Post, where: "status = '#{status}'")
```

```elixir
# SAFE: ? placeholder with a pinned parameter / keyword query
from(p in Post, where: fragment("title LIKE ?", ^"%#{term}%"))
Repo.all(from p in Post, where: p.status == ^status)
```

**Detection regex:** `fragment\(\s*"[^"]*#\{|where:\s*"[^"]*#\{`
**Checkpoint:** SA-PHOENIX-01
**Severity:** error

---

## Cross-Site Scripting (XSS)

### SA-PHOENIX-02: raw() in HEEx / ~H Templates

HEEx and `~H` sigils auto-escape interpolated expressions. Wrapping a value in `raw/1` (or `Phoenix.HTML.raw/1`) marks it as already-safe HTML and skips escaping. Applied to user input, this is stored/reflected XSS.

```heex
<%# VULNERABLE: raw/1 disables escaping %>
<div class="body"><%= raw(@comment.body) %></div>
```

```heex
<%# SAFE: default auto-escaping %>
<div class="body"><%= @comment.body %></div>
```

When sanitized HTML is genuinely required, run it through a vetted sanitizer (e.g. HtmlSanitizeEx) before calling `raw/1`.

**Detection regex:** `<%=\s*raw\s*\(|\{\{\s*raw\s*\(|\bPhoenix\.HTML\.raw\s*\(`
**Checkpoint:** SA-PHOENIX-02
**Severity:** error

---

## CSRF Protection

### SA-PHOENIX-03: protect_from_forgery Disabled

The generated `:browser` pipeline includes `plug :protect_from_forgery`, which verifies the CSRF token on state-changing requests. Commenting it out, or disabling `csrf_token`/`with_csrf_token` on forms, leaves cookie-authenticated endpoints open to forged cross-origin requests.

```elixir
# VULNERABLE: CSRF plug removed from the browser pipeline
pipeline :browser do
  plug :fetch_session
  plug :put_secure_browser_headers
  # plug :protect_from_forgery
end
```

```elixir
# SAFE: protect_from_forgery enabled before state-changing actions
pipeline :browser do
  plug :fetch_session
  plug :protect_from_forgery
  plug :put_secure_browser_headers
end
```

For token-authenticated JSON APIs (no cookie auth) CSRF protection is not needed, but those routes must not share the cookie-based `:browser` session.

**Detection regex:** `#\s*plug\s+:protect_from_forgery|csrf_token:\s*false|with_csrf_token:\s*false`
**Checkpoint:** SA-PHOENIX-03
**Severity:** error

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-EX-01 Atom exhaustion DoS | High | Immediate | Low |
| SA-EX-02 Code.eval code injection | Critical | Immediate | Low |
| SA-EX-03 Command injection | Critical | Immediate | Low |
| SA-EX-04 Secrets in logs | Medium | 1 week | Low |
| SA-PHOENIX-01 Ecto SQL injection | Critical | Immediate | Medium |
| SA-PHOENIX-02 HEEx raw() XSS | Critical | Immediate | Low |
| SA-PHOENIX-03 CSRF disabled | High | Immediate | Low |

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `rails-security.md` -- analogous MVC web-framework patterns
- `api-security.md` -- API-level security patterns
- Phoenix Security Guide: https://hexdocs.pm/phoenix/security.html
- Erlang Ecosystem Foundation Security WG: https://security.erlef.org/secure_coding_and_deployment_hardening/

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-06-13 | Initial release | Elixir/Phoenix language + framework expansion |

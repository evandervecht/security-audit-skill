# Vapor Security Patterns

Security patterns, common misconfigurations, and detection regexes for Vapor 4.x applications (Swift on the server). Vapor ships with safe defaults in many places — Fluent parameterizes queries, Leaf escapes template output, and `FileMiddleware` rejects traversal sequences — but the framework also exposes low-level escape hatches (`SQLKit` raw queries, `TLSConfiguration`, `CORSMiddleware`, `req.fileio`) where a single argument turns a safe API into an exploitable one. These checkpoints target those escape hatches with Vapor-specific anchors (`req.`, `app.`, `Environment.get`) so they do not overlap with the language-level `SA-SWIFT` checkpoints.

Scope: Vapor 4.x with Fluent/SQLKit, JWTKit, and the built-in `Sessions` and `CORSMiddleware` modules. File targets are `**/*.swift` (Vapor projects keep configuration in Swift code — `configure.swift`, `routes.swift` — rather than external config files).

---

## CORS Misconfiguration

### SA-VAPOR-01: CORSMiddleware with allowedOrigin: .all or .originBased

`CORSMiddleware.Configuration` accepts `allowedOrigin: .all`, which sends a literal `Access-Control-Allow-Origin: *`, and `allowedOrigin: .originBased`, which reflects any request `Origin` header back verbatim. Either way, any website on the internet can issue cross-origin requests to the API. The reflecting `.originBased` variant combined with `allowCredentials: true` — a very common pairing, because developers add it when cookie-authenticated requests start failing — lets a malicious page ride the victim's session cookie and read authenticated responses, which is a full account-takeover primitive against cookie-based auth.

```swift
// VULNERABLE: every origin may call the API, and credentialed
// requests (cookies, Authorization headers) are accepted cross-origin
public func configure(_ app: Application) throws {
    let corsConfiguration = CORSMiddleware.Configuration(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .PUT, .OPTIONS, .DELETE, .PATCH],
        allowedHeaders: [.accept, .authorization, .contentType, .origin],
        allowCredentials: true
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfiguration), at: .beginning)
}
```

```swift
// SECURE: enumerate the exact origins that legitimately embed the API
public func configure(_ app: Application) throws {
    let corsConfiguration = CORSMiddleware.Configuration(
        allowedOrigin: .any(["https://app.example.com", "https://admin.example.com"]),
        allowedMethods: [.GET, .POST, .PUT, .OPTIONS, .DELETE, .PATCH],
        allowedHeaders: [.accept, .authorization, .contentType, .origin],
        allowCredentials: true
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfiguration), at: .beginning)
}
```

**Security implication:** With a wildcard origin, the browser's same-origin policy no longer protects the API. `.all` emits a literal `*`; per the Fetch spec browsers refuse to expose credentialed responses under `*`, so its blast radius is everything readable pre-auth (still fatal for intranet or IP-authenticated services). `.originBased` reflects the caller's origin verbatim — which browsers *do* accept with credentials — so with `allowCredentials: true` it exposes everything the logged-in user can read or do. Use `.any([...])` with an explicit HTTPS allowlist, or `.custom(...)` when the origin must be computed.

**Detection regex:** `allowedOrigin:\s*\.(all|originBased)\b`
**Checkpoint:** SA-VAPOR-01
**Severity:** warning

---

## Injection

### SA-VAPOR-02: Raw SQL with Unbound Swift String Interpolation

SQLKit's `db.raw(...)` (and `SQLQueryString` generally) accepts a string that supports Swift interpolation. Plain `\(value)` interpolation splices the value directly into the SQL text (newer SQLKit deprecates the unlabeled form in favor of an explicit `\(unsafeRaw:)` label — both splice raw text); SQLKit only parameterizes interpolations that use the `\(bind:)` label. Interpolating anything derived from `req.parameters`, `req.query`, or decoded request content is classic SQL injection.

```swift
// VULNERABLE: user-controlled email spliced into the SQL string
func search(req: Request) async throws -> [Row] {
    let email = req.parameters.get("email") ?? ""
    let sql = req.db as! SQLDatabase
    return try await sql.raw("SELECT id, name FROM users WHERE email = '\(email)'").all()
}
```

```swift
// SECURE: \(bind:) turns the interpolation into a driver-level placeholder
func search(req: Request) async throws -> [Row] {
    let email = req.parameters.get("email") ?? ""
    let sql = req.db as! SQLDatabase
    return try await sql.raw("SELECT id, name FROM users WHERE email = \(bind: email)").all()
}

// SECURE: or avoid raw SQL entirely with the Fluent query builder
func search(req: Request) async throws -> [User] {
    let email = req.parameters.get("email") ?? ""
    return try await User.query(on: req.db).filter(\.$email == email).all()
}
```

**Security implication:** An attacker supplying `' OR '1'='1` (or a stacked `; DROP TABLE` payload on drivers that allow it) can read or destroy arbitrary data. The fix is mechanical: every raw-query interpolation of a runtime value must use `\(bind:)`; identifiers that cannot be bound (table/column names) must be resolved from a hardcoded allowlist and interpolated with `\(ident:)`. The detection regex matches unlabeled interpolations and the raw-splicing `\(raw:)`/`\(unsafeRaw:)` labels inside `.raw("...")`, and deliberately does not match safe labels such as `\(bind: email)`, `\(ident:)`, or `\(literal:)`.

**Detection regex:** `(\.raw|SQLQueryString)\s*\(\s*"[^"]*\\\(([A-Za-z_][A-Za-z0-9_.]*\)|(unsafeRaw|raw)\s*:)`
**Checkpoint:** SA-VAPOR-02
**Severity:** error

---

## Transport Security

### SA-VAPOR-03: TLS certificateVerification = .none

`TLSConfiguration` (NIOSSL) controls TLS for Vapor's database connections, HTTP client, and server. Setting `certificateVerification = .none` disables both chain validation and hostname verification. It usually enters the codebase as a workaround for a self-signed database certificate in development and then ships to production.

```swift
// VULNERABLE: the Postgres connection accepts ANY certificate
public func configure(_ app: Application) throws {
    var tls = TLSConfiguration.makeClientConfiguration()
    tls.certificateVerification = .none
    app.databases.use(.postgres(
        hostname: Environment.get("DATABASE_HOST") ?? "localhost",
        username: "vapor",
        password: databasePassword,
        database: "vapor",
        tlsConfiguration: tls
    ), as: .psql)
}
```

```swift
// SECURE: full verification, trusting the internal CA that signed the DB cert
public func configure(_ app: Application) throws {
    var tls = TLSConfiguration.makeClientConfiguration()
    tls.certificateVerification = .fullVerification
    tls.trustRoots = .file("/etc/ssl/certs/internal-ca.pem")
    app.databases.use(.postgres(
        hostname: Environment.get("DATABASE_HOST") ?? "localhost",
        username: "vapor",
        password: databasePassword,
        database: "vapor",
        tlsConfiguration: tls
    ), as: .psql)
}
```

(Both examples assume `databasePassword` was loaded with a fail-fast `guard let` per SA-VAPOR-04.)

**Security implication:** With verification off, any on-path attacker (compromised LB, rogue Wi-Fi, poisoned DNS) can terminate the TLS connection with their own certificate and read or rewrite every query and credential in transit — TLS is reduced to obfuscation. `.noHostnameVerification` is only marginally better and deserves manual review. The correct fix for self-signed infrastructure is `.fullVerification` plus `trustRoots` pointing at the internal CA, never `.none`.

**Detection regex:** `certificateVerification\s*[:=]\s*\.none`
**Checkpoint:** SA-VAPOR-03
**Severity:** error

---

## Secrets Management

### SA-VAPOR-04: Hardcoded Fallback Secret After Environment.get

`Environment.get` returns an optional, and the tempting one-liner is to nil-coalesce into a string literal so the app boots without configuration. For signing keys, API keys, and passwords this means the literal — committed to source control — silently becomes the production secret whenever the environment variable is missing or misspelled.

```swift
// VULNERABLE: the committed literal becomes the JWT signing key
// whenever JWT_SECRET is unset (or the var name has a typo)
public func configure(_ app: Application) throws {
    let jwtSecret = Environment.get("JWT_SECRET") ?? "dev-secret-do-not-use"
    app.jwt.signers.use(.hs256(key: jwtSecret))
}
```

```swift
// SECURE: fail fast at boot when the secret is absent;
// nil-coalescing stays fine for non-secret values like ports
public func configure(_ app: Application) throws {
    guard let jwtSecret = Environment.get("JWT_SECRET") else {
        app.logger.critical("JWT_SECRET is not set; refusing to start")
        throw Abort(.internalServerError, reason: "Missing JWT_SECRET")
    }
    app.jwt.signers.use(.hs256(key: jwtSecret))

    let listenPort = Environment.get("HTTP_PORT") ?? "8080"
    app.http.server.configuration.port = Int(listenPort) ?? 8080
}
```

**Security implication:** Anyone with read access to the repository (or to a leaked image layer) learns the fallback and can mint valid JWTs, call third-party APIs on the app's behalf, or authenticate to the database. Because the fallback engages silently, the vulnerable state is invisible in production until exploited. The regex is scoped to variable names that *end* in a secret keyword (`SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `PASS`), so harmless defaults such as `Environment.get("HTTP_PORT") ?? "8080"`, `Environment.get("TOKEN_LIFETIME") ?? "3600"`, or `Environment.get("KEY_LENGTH") ?? "32"` do not alert; even an empty-string fallback for a secret-shaped name is flagged.

**Detection regex:** `Environment\.get\s*\(\s*"[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD|PASS)"\s*\)\s*\?\?\s*"`
**Checkpoint:** SA-VAPOR-04
**Severity:** error

---

## Path Traversal

### SA-VAPOR-05: streamFile Path Built from Request Parameters

`req.fileio.streamFile(at:)` streams any path on disk that the process can read. Concatenating a route parameter (or catchall) into the path lets an attacker walk out of the intended directory with `../` sequences — Vapor does not canonicalize or sandbox the argument (only the higher-level `FileMiddleware` does traversal checks).

```swift
// VULNERABLE: GET /download/..%2F..%2F.env escapes the downloads directory
func routes(_ app: Application) throws {
    app.get("download", ":name") { req -> Response in
        let base = app.directory.publicDirectory + "downloads/"
        return req.fileio.streamFile(at: base + req.parameters.get("name")!)
    }
}
```

```swift
// SECURE: resolve the user-supplied key against an allowlist,
// so the streamed path never contains request-controlled bytes
func routes(_ app: Application) throws {
    let allowedReports = ["latest": "latest-report.pdf", "annual": "annual-report.pdf"]

    app.get("download", ":name") { req -> Response in
        let requested = req.parameters.get("name") ?? ""
        guard let filename = allowedReports[requested] else {
            throw Abort(.notFound)
        }
        let base = app.directory.publicDirectory + "downloads/"
        return req.fileio.streamFile(at: base + filename)
    }
}
```

**Security implication:** Traversal out of the base directory exposes `.env` files, sqlite databases, TLS keys, and source code — frequently escalating to full credential compromise. Where an allowlist is impractical, canonicalize the joined path and verify the prefix: `URL(fileURLWithPath: base + name).standardizedFileURL.path.hasPrefix(base)`, and additionally reject any component equal to `..`. Serving an entire directory is better delegated to `FileMiddleware`, which performs these checks itself. The regex flags paths concatenated from `req.parameters` and string interpolations that embed `req.`-derived values; interpolating only server-side configuration (e.g. `"\(app.directory.publicDirectory)reports/summary.pdf"`) does not alert. Request data laundered through an intermediate variable needs manual review.

**Detection regex:** `streamFile\s*\(\s*at:\s*"[^"]*\\\([^)"]*req\.|streamFile\s*\(\s*at:[^)]*req\.parameters`
**Checkpoint:** SA-VAPOR-05
**Severity:** error

---

## Session & Cookie Security

### SA-VAPOR-06: Session Cookie Factory with isSecure: false

Vapor's sessions are configured through a cookie factory that returns an `HTTPCookies.Value`. Setting `isSecure: false` (often copied from an HTTP-only local setup) makes the browser attach the session cookie to plain-HTTP requests; disabling `isHTTPOnly` additionally exposes it to any injected script. Note that Vapor's *default* `SessionsConfiguration.default()` factory also ships `isSecure: false, isHTTPOnly: false` — so an app that never customizes the factory is insecure too; the regex only catches the explicit literals, and the missing-factory case belongs to manual review.

```swift
// VULNERABLE: session cookie sent over cleartext HTTP and readable from JS
public func configure(_ app: Application) throws {
    app.sessions.configuration = .init(cookieName: "vapor-session") { sessionID in
        HTTPCookies.Value(string: sessionID.string, isSecure: false, isHTTPOnly: false, sameSite: .lax)
    }
    app.middleware.use(app.sessions.middleware)
}
```

```swift
// SECURE: Secure + HttpOnly + SameSite on the session cookie
public func configure(_ app: Application) throws {
    app.sessions.configuration = .init(cookieName: "vapor-session") { sessionID in
        HTTPCookies.Value(string: sessionID.string, isSecure: true, isHTTPOnly: true, sameSite: .lax)
    }
    app.middleware.use(app.sessions.middleware)
}
```

**Security implication:** Without `Secure`, a single HTTP request — an `http://` bookmark, a captive portal redirect, an attacker-injected image URL — leaks the session ID to anyone on the network path, and session hijacking follows. Without `HttpOnly`, any XSS bug is upgraded to session theft. Production Vapor apps should set `isSecure: true`, `isHTTPOnly: true`, and an appropriate `sameSite` value, and terminate TLS in front of the app (behind a proxy the cookie flags still apply to the browser). One legitimate exception exists: a deliberately JS-readable, non-session cookie such as an XSRF-token mirror will also match `isHTTPOnly: false` — triage such matches manually rather than blanket-suppressing the checkpoint.

**Detection regex:** `isSecure\s*:\s*false|isHTTPOnly\s*:\s*false`
**Checkpoint:** SA-VAPOR-06
**Severity:** warning

---

## Additional Hardening Notes (no dedicated checkpoint)

- **Middleware order matters.** `CORSMiddleware` must be registered `at: .beginning` (before error middleware) or preflight responses lose their headers on error paths.
- **Error middleware in production.** Keep the default `ErrorMiddleware`; custom error handlers that echo `error.localizedDescription` for unexpected errors can leak file paths and query fragments.
- **Leaf templates.** `#(variable)` escapes HTML; `#unsafeHTML(variable)` does not — treat any `unsafeHTML` on request-derived data as XSS (covered by language-level review, not a SA-VAPOR checkpoint).
- **FileMiddleware over hand-rolled file routes.** It handles traversal, ranges, and ETags; prefer it to `req.fileio` for static content.
- **Password hashing.** Use `app.password` / `req.password` (Bcrypt by default) rather than manual SHA digests.

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-VAPOR-02: raw SQL interpolation injection | Critical | Immediate | Low |
| SA-VAPOR-03: certificateVerification .none | Critical | Immediate | Low |
| SA-VAPOR-04: hardcoded fallback secret | High | Immediate | Low |
| SA-VAPOR-05: streamFile path traversal | High | Immediate | Medium |
| SA-VAPOR-01: CORS allowedOrigin .all/.originBased | High | 1 week | Low |
| SA-VAPOR-06: session cookie isSecure false | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `swift-security-features.md` — Swift language-level patterns (SA-SWIFT)
- `path-traversal-prevention.md` — General traversal defenses
- `api-security.md` — API-level CORS and auth guidance
- `ktor-security.md` — Comparable JVM server-framework patterns
- `cryptography-guide.md` — Key management and TLS guidance

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

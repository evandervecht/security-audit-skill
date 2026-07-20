# Ktor Security Patterns

Security patterns, common misconfigurations, and detection regexes for Ktor (2.x/3.x) server and client applications. Ktor is unopinionated by design: CORS, authentication, session hardening, and TLS validation are all opt-in plugins, so a handful of one-line conveniences (`anyHost()`, `JWT.decode()`, `trustManager = object : X509TrustManager`, `cookie.secure = false`) silently remove entire protection layers. These checkpoints are deliberately anchored to Ktor APIs (`install(CORS)`, `call.respondText`, `call.respondFile`, the `https { }` engine block, the Sessions cookie builder) so they complement, rather than duplicate, the generic Kotlin `SA-KT-*` checkpoints.

---

## CORS Misconfiguration

### SA-KTOR-01: Wildcard CORS via anyHost()

Ktor's CORS plugin refuses cross-origin requests unless origins are explicitly allowed. `anyHost()` is the documented "just make it work" switch that reflects every `Origin` header, turning the API into a public cross-origin endpoint. The Ktor docs themselves warn not to ship it to production.

```kotlin
// VULNERABLE: every website on the internet may call this API from the browser
fun Application.configureCors() {
    install(CORS) {
        anyHost()
        allowHeader(HttpHeaders.ContentType)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
    }
}
```

```kotlin
// SECURE: enumerate the exact origins that legitimately embed this API
fun Application.configureCors() {
    install(CORS) {
        allowHost("app.example.com", schemes = listOf("https"))
        allowHost("admin.example.com", schemes = listOf("https"))
        allowHeader(HttpHeaders.ContentType)
        allowMethod(HttpMethod.Put)
    }
}
```

**Security implication:** With `anyHost()`, any attacker-controlled page can issue cross-origin requests to the API and read the responses. For APIs authenticated by anything ambient (IP allowlists, mTLS terminated upstream, tokens injected by a gateway) this leaks data directly; even for token-authenticated APIs it removes the browser's same-origin backstop and makes CSRF-style abuse and data scraping trivial.

**Detection regex:** `\banyHost\s*\(\s*\)`
**Checkpoint:** SA-KTOR-01
**Severity:** warning

---

### SA-KTOR-02: Credentialed Wildcard CORS (anyHost + allowCredentials)

Combining `anyHost()` with `allowCredentials = true` tells browsers to attach cookies and HTTP auth to cross-origin requests from *any* origin and to let that origin read the response. Browsers forbid the literal `Access-Control-Allow-Origin: *` with credentials, so Ktor reflects the request origin instead -- which is exactly the bypass attackers need.

```kotlin
// VULNERABLE: any site can ride the victim's session cookie and read the response
fun Application.configureCors() {
    install(CORS) {
        anyHost()
        allowCredentials = true
        allowHeader(HttpHeaders.Authorization)
        allowMethod(HttpMethod.Post)
    }
}
```

```kotlin
// SECURE: credentials only for a pinned, HTTPS-only origin allowlist
fun Application.configureCors() {
    install(CORS) {
        allowHost("app.example.com", schemes = listOf("https"))
        allowCredentials = true
        allowHeader(HttpHeaders.Authorization)
        allowMethod(HttpMethod.Post)
    }
}
```

**Security implication:** This is a full cross-site account takeover primitive: `evil.example` scripts can call every authenticated endpoint as the logged-in victim (session cookie attached automatically) and exfiltrate the JSON responses. It is strictly worse than classic CSRF because the attacker also *reads* data, not just mutates it. Treat as an error, not hygiene.

**Detection regex:** `anyHost\s*\(\s*\)[^}]*allowCredentials\s*=\s*true|allowCredentials\s*=\s*true[^}]*anyHost\s*\(\s*\)`
(Note: this pairing spans lines inside the `install(CORS)` block; the scanner implements it as "file contains both `anyHost()` and `allowCredentials = true`".)
**Checkpoint:** SA-KTOR-02
**Severity:** error

---

## Authentication & Authorization

### SA-KTOR-03: JWT Accepted Without Signature Verification

Ktor's JWT auth is built on auth0 java-jwt. Two patterns skip signature verification entirely: signing/accepting tokens with `Algorithm.none()`, and reading claims via `JWT.decode(token)` (decode parses, it does **not** verify). Handlers that pull the `Authorization` header and `JWT.decode` it trust whatever the client sent.

```kotlin
// VULNERABLE: claims are trusted straight from the wire; signature never checked
fun Route.profileRoutes() {
    get("/profile") {
        val token = call.request.header("Authorization")?.removePrefix("Bearer ") ?: ""
        val decoded = JWT.decode(token)
        val userId = decoded.getClaim("sub").asString()
        call.respondText("Profile for user " + userId)
    }
}

// VULNERABLE: unsigned tokens ("alg": "none") are forgeable by anyone
fun issueLegacyToken(subject: String): String =
    JWT.create().withSubject(subject).sign(Algorithm.none())
```

```kotlin
// SECURE: install the JWT plugin with a pinned algorithm, issuer, and claim validation
fun Application.configureAuth(jwtSecret: String, issuer: String) {
    install(Authentication) {
        jwt("auth-jwt") {
            verifier(
                JWT.require(Algorithm.HMAC256(jwtSecret))
                    .withIssuer(issuer)
                    .build()
            )
            validate { credential ->
                if (credential.payload.getClaim("sub").asString().isNotEmpty())
                    JWTPrincipal(credential.payload) else null
            }
        }
    }
}
```

**Security implication:** An attacker mints a token with any `sub`/`role` claim (or strips the signature with `alg: none`) and is accepted as any user, including admins. This is a complete authentication bypass. Always build a verifier via `JWT.require(algorithm)` -- which pins the algorithm and rejects `none` -- and route protected endpoints through `authenticate { }`.

**Detection regex:** `Algorithm\.none\s*\(\s*\)|\bJWT\.decode\s*\(`
(The `\b` keeps wrapper types such as `VerifiedJWT.decode(...)` from matching; only the auth0 `JWT` class itself is flagged.)
**Checkpoint:** SA-KTOR-03
**Severity:** error

---

### SA-KTOR-04: Hardcoded JWT/HMAC Signing Secret

Passing a string literal to `Algorithm.HMAC256(...)` (or HMAC384/512) bakes the token-signing key into source control and every build artifact.

```kotlin
// VULNERABLE: signing key lives in git history and in every JAR
fun Application.configureJwt() {
    val algorithm = Algorithm.HMAC256("super-secret-signing-key-2024")
    install(Authentication) {
        jwt("auth-jwt") {
            verifier(JWT.require(algorithm).withIssuer("example.com").build())
            validate { credential -> JWTPrincipal(credential.payload) }
        }
    }
}
```

```kotlin
// SECURE: key comes from application config / environment, never from a literal
fun Application.configureJwt() {
    val secret = environment.config.property("jwt.secret").getString()
    val algorithm = Algorithm.HMAC256(secret)
    install(Authentication) {
        jwt("auth-jwt") {
            verifier(JWT.require(algorithm).withIssuer("example.com").build())
            validate { credential -> JWTPrincipal(credential.payload) }
        }
    }
}
```

**Security implication:** Anyone with repo read access (or a leaked JAR, or a public fork) can forge valid session tokens for arbitrary users forever -- HMAC keys are symmetric, so the verification key *is* the signing key. Rotation requires a code deploy. Load the secret from `environment.config` / `System.getenv` backed by a secrets manager, and rotate on any suspected exposure.

**Detection regex:** `Algorithm\.HMAC(256|384|512)\s*\(\s*"[^"$]+"`
(Only pure string literals match; Kotlin string templates such as `Algorithm.HMAC256("${System.getenv("JWT_SECRET")}")` resolve at runtime and are not hardcoded secrets.)
**Checkpoint:** SA-KTOR-04
**Severity:** error

---

## Cross-Site Scripting (XSS)

### SA-KTOR-05: Reflected XSS via respondText(..., ContentType.Text.Html)

Ktor performs no output encoding: `call.respondText(html, ContentType.Text.Html)` ships bytes verbatim with an HTML content type. Interpolating `call.parameters` / `call.request.queryParameters` into that string is textbook reflected XSS.

```kotlin
// VULNERABLE: query parameter reflected verbatim into an HTML response
fun Route.searchRoutes() {
    get("/search") {
        val query = call.request.queryParameters["q"] ?: ""
        call.respondText("<h1>Results for $query</h1><p>No items matched.</p>", ContentType.Text.Html)
    }
}
```

```kotlin
// SECURE: kotlinx.html DSL escapes text nodes; plain text needs no HTML type
fun Route.searchRoutes() {
    get("/search") {
        val query = call.request.queryParameters["q"] ?: ""
        call.respondHtml {
            body {
                h1 { +"Results for $query" }   // '+' text nodes are auto-escaped
                p { +"No items matched." }
            }
        }
    }
    get("/greet") {
        val name = call.parameters["name"] ?: "guest"
        call.respondText("Hello, $name", ContentType.Text.Plain)
    }
}
```

**Security implication:** `<script>` (or event-handler attributes) in the reflected parameter execute in the victim's browser in the application's origin -- session-cookie theft, token exfiltration, or full UI takeover, deliverable by a crafted link. Render HTML through `respondHtml`/kotlinx.html (auto-escaping), a template engine with escaping enabled (FreeMarker/Thymeleaf), or keep dynamic responses `ContentType.Text.Plain`.

**Detection regex:** `respondText\s*\(\s*(text\s*=\s*)?"[^"]*\$[A-Za-z_{].*ContentType\.Text\.Html|respondText\s*\(\s*contentType\s*=\s*ContentType\.Text\.Html\s*,\s*text\s*=\s*"[^"]*\$[A-Za-z_{]`
(Covers positional and named-argument forms, including nested-quote interpolations like `${call.parameters["q"]}`. The `\$[A-Za-z_{]` requires a real Kotlin interpolation — literal dollars such as `"under $10"` do not match. Pre-built strings passed by variable need manual review.)
**Checkpoint:** SA-KTOR-05
**Severity:** error

---

## Path Traversal

### SA-KTOR-06: respondFile Fed Directly From Request Input

`call.respondFile(file: File)` streams any `File` it is given. Constructing that `File` yourself from `call.parameters` / `call.request.queryParameters` without canonicalization lets `../../` sequences (and absolute paths) walk out of the intended directory — `File(base, "../..")` resolution does *not* jail the child path. By contrast, the two-argument overload `respondFile(baseDir, fileName)` routes through Ktor's `combineSafe`, which normalizes the relative path and rejects `..` escapes and rooted paths, so it is safe even with request-derived filenames.

```kotlin
// VULNERABLE: ?file=../../etc/passwd escapes the upload directory
fun Route.downloadRoutes(uploadDir: File, reportsDir: File) {
    get("/download") {
        call.respondFile(File(uploadDir, call.parameters["file"]!!))
    }
    get("/reports") {
        call.respondFile(File(reportsDir, call.request.queryParameters["name"]!!))
    }
}
```

```kotlin
// SECURE: canonicalize, then verify the result is still inside the base directory
fun Route.downloadRoutes(uploadDir: File) {
    get("/download") {
        val requested = call.parameters["file"]
        if (requested == null) {
            call.respond(HttpStatusCode.BadRequest)
            return@get
        }
        val target = File(uploadDir, requested).canonicalFile
        if (!target.path.startsWith(uploadDir.canonicalPath + File.separator)) {
            call.respond(HttpStatusCode.Forbidden)
            return@get
        }
        call.respondFile(target)
    }

    // ALSO SAFE: the two-argument overload jails the path via combineSafe,
    // throwing on "../" escapes and rooted paths before any file is opened
    get("/manuals") {
        call.respondFile(uploadDir, call.parameters["file"] ?: "index.html")
    }
}
```

**Security implication:** Arbitrary file read as the server process: TLS keys, `application.conf` with database credentials, `/etc/passwd`, other tenants' uploads. Prefer Ktor's `staticFiles()` for public assets; for parameterized downloads, use the `respondFile(baseDir, fileName)` overload, or resolve to `canonicalFile` and enforce a `startsWith(baseDir.canonicalPath + File.separator)` jail check (or map IDs to filenames and never accept paths at all).

**Detection regex:** `respondFile\s*\(\s*([A-Za-z_.]*\.)?File\s*\([^()"]*call\.(parameters|request|receive)`
(Matches a `File` constructed inline from request input, e.g. `respondFile(File(dir, call.parameters[...]))` or `respondFile(java.io.File(call.request...))`. The `([A-Za-z_.]*\.)?File` group requires the bare `File` constructor — optionally package-qualified — so sanitizing helpers are not flagged even when their names end in `File` (`respondFile(archiveFile(dir, call.parameters[...]))`, `respondFile(resolveUnderBase(dir, call.parameters[...]))`). The two-argument `respondFile(baseDir, call.parameters[...])` overload is deliberately *not* matched — it is `combineSafe`-jailed. The generic `File(...call.parameters...)` construction is already covered by SA-KT-11; this checkpoint targets the Ktor `respondFile` response API to avoid duplicate findings.)
**Checkpoint:** SA-KTOR-06
**Severity:** error

---

## Transport Security

### SA-KTOR-07: Trust-All TrustManager in the HttpClient https Block

Ktor's `HttpClient` engine config exposes `https { trustManager = ... }`. Assigning an empty `object : X509TrustManager` (the classic fix for internal/self-signed certs) accepts every certificate chain, silently disabling TLS server authentication for all requests that client makes.

```kotlin
// VULNERABLE: accepts any certificate -- MITM goes unnoticed
fun buildInternalClient(): HttpClient =
    HttpClient(CIO) {
        engine {
            https {
                trustManager = object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }
            }
        }
    }
```

```kotlin
// SECURE: trust the internal CA explicitly via a TrustManagerFactory-backed store
fun buildInternalClient(caStorePath: String, storePassword: CharArray): HttpClient {
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    FileInputStream(caStorePath).use { keyStore.load(it, storePassword) }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(keyStore)
    val caTrustManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    return HttpClient(CIO) {
        engine {
            https {
                trustManager = caTrustManager
            }
        }
    }
}
```

**Security implication:** Any on-path attacker (compromised LAN, rogue Wi-Fi, hijacked BGP, malicious proxy) can present a self-signed cert and read/modify everything the client sends -- service credentials, bearer tokens, customer data. Because the failure is silent, these "temporary" dev shims routinely reach production. Ship the internal CA in a trust store (or use certificate pinning) instead. This checkpoint targets the Ktor `trustManager =` builder property specifically; the generic anonymous-TrustManager pattern is covered by SA-KT-04.

**Detection regex:** `trustManager\s*=\s*object\s*:\s*X509TrustManager|trustManager\s*=\s*[A-Za-z_.]*(([Tt]rustAll|[Aa]cceptAll)([A-Z]|\b)|[Ii]nsecure|[Uu]nsafe|[Nn]oVerify)`
(Catches anonymous trust-all objects plus tell-tale variable names like `trustAllCerts` / `insecureTrustManager`, while benign names such as `trustAllowlistManager` do not match.)
**Checkpoint:** SA-KTOR-07
**Severity:** error

---

## Session Security

### SA-KTOR-08: Session Cookie With secure/httpOnly Explicitly Disabled

Ktor's Sessions plugin exposes the cookie flags on the builder. `cookie.httpOnly` defaults to `true` and `cookie.secure` should be enabled behind HTTPS; code that explicitly sets either to `false` (commonly "so it works on localhost") strips session-theft protections in every environment the code ships to.

```kotlin
// VULNERABLE: session id readable by page scripts and sent over plain HTTP
fun Application.configureSessions() {
    install(Sessions) {
        cookie<UserSession>("USER_SESSION") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = 3600
            cookie.secure = false
            cookie.httpOnly = false
        }
    }
}
```

```kotlin
// SECURE: HTTPS-only, script-inaccessible, SameSite-pinned session cookie
fun Application.configureSessions() {
    install(Sessions) {
        cookie<UserSession>("USER_SESSION") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = 3600
            cookie.secure = true
            cookie.httpOnly = true
            cookie.extensions["SameSite"] = "Strict"
        }
    }
}
```

**Security implication:** `secure = false` lets any downgrade to HTTP (or a single http:// asset link) leak the session id to network observers; `httpOnly = false` upgrades every XSS bug into full session hijacking, since `document.cookie` exposes the id to injected scripts. Gate localhost convenience behind a dev-mode config flag rather than hardcoding `false`.

**Detection regex:** `cookie\.secure\s*=\s*false|cookie\.httpOnly\s*=\s*false`
**Checkpoint:** SA-KTOR-08
**Severity:** warning

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-KTOR-02: credentialed wildcard CORS | Critical | Immediate | Low |
| SA-KTOR-03: JWT accepted without verification | Critical | Immediate | Medium |
| SA-KTOR-07: trust-all TrustManager in HttpClient | Critical | Immediate | Medium |
| SA-KTOR-04: hardcoded HMAC signing secret | High | Immediate (rotate key) | Low |
| SA-KTOR-05: reflected XSS via respondText HTML | High | Immediate | Low |
| SA-KTOR-06: path traversal via respondFile | High | 1 week | Medium |
| SA-KTOR-01: wildcard CORS anyHost() | Medium | 1 week | Low |
| SA-KTOR-08: insecure session cookie flags | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `kotlin-security-features.md` — Kotlin language-level patterns (SA-KT-*: command/SQL injection, weak crypto, generic trust-all TrustManager, deserialization)
- `spring-security.md` — Comparable JVM server framework patterns
- `api-security.md` — General API hardening (CORS, auth, rate limiting)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

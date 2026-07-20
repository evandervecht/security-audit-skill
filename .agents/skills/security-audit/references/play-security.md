# Play Framework Security Patterns

Security patterns, common misconfigurations, and detection regexes for Play Framework 2.9/3.x applications (Scala). Play enables a strong default filter chain — `CSRFFilter`, `AllowedHostsFilter`, and `SecurityHeadersFilter` are all on by default — and Twirl templates auto-escape interpolated values. In practice, most Play vulnerabilities are introduced by *turning these defaults off* in `conf/application.conf` or by reaching for raw APIs (`Html(...)`, Anorm/Slick string interpolation). These checkpoints therefore target both Scala sources (`**/*.scala`), Twirl templates (`**/*.scala.html`), and HOCON configuration (`**/*.conf`).

The language-level `SA-SCALA` checkpoints cover generic Scala issues (deserialization, `Runtime.exec`, weak hashing); the SA-PLAY set below is scoped to Play-specific APIs and configuration keys so the two namespaces do not double-report.

---

## CSRF Protection

### SA-PLAY-01: CSRFFilter Disabled in application.conf

Play enables `play.filters.csrf.CSRFFilter` by default, requiring a CSRF token on state-changing form posts. Adding the filter to `play.filters.disabled` removes the protection for the entire application — a change that usually appears when a mobile or third-party client cannot easily send the token. (Overriding `play.filters.enabled` with a list that simply omits the filter has the same effect; an omission cannot be caught by a regex and belongs to manual review.)

```hocon
# VULNERABLE: application.conf — CSRF checks removed application-wide
play.http.secret.key = ${?APPLICATION_SECRET}

# Disable CSRF checks so the mobile client can POST without a token
play.filters.disabled += "play.filters.csrf.CSRFFilter"
```

```hocon
# SECURE: keep the filter; non-browser clients send the token in a header
play.http.secret.key = ${?APPLICATION_SECRET}

play.filters.enabled += "play.filters.csrf.CSRFFilter"
play.filters.csrf.header.name = "Csrf-Token"
# A single legacy endpoint that genuinely cannot send a token can be
# exempted in the routes file with the "+ nocsrf" route modifier:
#   + nocsrf
#   POST  /legacy/webhook  controllers.WebhookController.receive
```

```scala
// Twirl form with the token (secure usage in templates)
@helper.form(routes.OrderController.submit()) {
  @helper.CSRF.formField
  ...
}
```

**Security implication:** With the filter disabled, any website can submit authenticated state-changing requests (transfer funds, change email, escalate roles) using the victim's session cookie. Play offers per-route (`@AddCSRFToken` / route modifier `+ nocsrf`) and header-based escape hatches, so there is never a good reason to disable the filter globally. If a single legacy endpoint must be exempt, exempt that route, not the application.

**Detection regex:** `play\.filters\.disabled\s*(\+=|=).*"play\.filters\.csrf\.CSRFFilter"`
(Covers both the `disabled += "..."` append form and a direct `disabled = ["..."]` list assignment; HOCON has no `-=` operator, so there is no removal syntax to match.)
**Checkpoint:** SA-PLAY-01
**Severity:** error

---

## Cross-Site Scripting (XSS)

### SA-PLAY-02: @Html(...) Rendering User Data in Twirl Templates

Twirl escapes every `@value` interpolation by default. Wrapping a value in `@Html(...)` opts out of escaping and injects the string as raw markup. When the wrapped value contains user-controlled data (comments, profile fields, CMS content), this is a stored or reflected XSS vector. The same applies to `Html(...)` built in controllers and passed to templates.

```html
@* VULNERABLE: comment body rendered as raw HTML *@
@(comment: models.Comment)
<article class="comment">
  <span class="author">@comment.author</span>
  <div class="body">
    @Html(comment.body)
  </div>
</article>
```

```html
@* SECURE: rely on Twirl's default escaping (or escape explicitly) *@
@(comment: models.Comment)
<article class="comment">
  <span class="author">@comment.author</span>
  <div class="body">
    @HtmlFormat.escape(comment.body)
  </div>
</article>
```

**Security implication:** A single `<script>` payload in a comment executes in every reader's browser: session-riding, credential phishing, and — combined with SA-PLAY-05 — outright session-cookie theft. If rich text is a genuine requirement, sanitize server-side with an allowlist sanitizer (e.g. OWASP Java HTML Sanitizer) *before* wrapping in `Html`, and treat the sanitizer as the single choke point. `@HtmlFormat.escape(...)` and plain `@value` interpolation are always safe; the regex matches only the raw `@Html(` form.

**Detection regex:** `@Html\s*\(`
**Checkpoint:** SA-PLAY-02
**Severity:** error

---

## Injection

### SA-PLAY-03: Anorm SQL(s"...") Interpolation and Slick #$ Splicing

Anorm's `SQL(...)` takes a plain string: building it with the `s"..."` interpolator splices user input straight into the SQL text. Slick's `sql"..."` interpolator is safe for `$value` (it binds a parameter) but the `#$value` form splices raw SQL — a frequently misunderstood distinction.

```scala
// VULNERABLE: Anorm query text built with the s-interpolator
def findByName(name: String)(implicit c: Connection): Option[User] =
  SQL(s"SELECT id, name, email FROM users WHERE name = '$name'")
    .as(parser.singleOpt)

// VULNERABLE: Slick #$ splices sortColumn into the statement unquoted
def list(sortColumn: String) =
  sql"SELECT id, name FROM users ORDER BY #$sortColumn".as[(Int, String)]
```

```scala
// SECURE: Anorm named placeholders bound with .on(...)
def findByName(name: String)(implicit c: Connection): Option[User] =
  SQL("SELECT id, name, email FROM users WHERE name = {name}")
    .on("name" -> name)
    .as(parser.singleOpt)

// SECURE: Slick $value binds a parameter; structural variation (sort column)
// resolves to literal queries instead of splicing text with #$
def list(sortColumn: String) = {
  val query = sortColumn match {
    case "name" => sql"SELECT id, name FROM users ORDER BY name"
    case _      => sql"SELECT id, name FROM users ORDER BY id"
  }
  query.as[(Int, String)]
}
```

**Security implication:** Interpolated queries allow classic SQL injection: authentication bypass with `' OR '1'='1`, data exfiltration via UNION, and on some drivers stacked statements. Anorm supports `{name}` placeholders with `.on(...)` (or the `anorm.SqlStringInterpolation` `SQL"..."` interpolator, which binds like Slick's `$`); Slick binds `$value` automatically. Anything that must vary structurally — table or column names — cannot be bound; because `#$` always splices raw text into the statement, resolve such variation to literal queries (or allowlisted constants) rather than splicing. The regex flags `SQL(s"..."` containing `$` and `#$` splices inside `sql"..."`/`sqlu"..."` literals (including triple-quoted `sql"""` forms). Scoping the `#$` branch to the sql interpolators keeps benign interpolations such as `s"$baseUrl#$anchor"` or `s"color: #$hex"` from alerting.

**Detection regex:** `\bSQL\s*\(\s*s"+[^"]*\$|\bsqlu?"+[^"]*#\$`
**Checkpoint:** SA-PLAY-03
**Severity:** error

---

## CORS Misconfiguration

### SA-PLAY-04: CORSFilter with allowedOrigins = null or ["*"]

In Play's CORS filter, `allowedOrigins = null` means "allow every origin". Because `play.filters.cors.supportsCredentials` defaults to **true**, the null form reflects arbitrary origins on credentialed requests — the worst possible CORS posture for a cookie-authenticated API. An `allowedOrigins = ["*"]` entry is matched *literally* by Play (origins are compared as exact strings), so it does not actually open the API — but it appears in configs written with wildcard intent, silently breaks the allowlist for the real origins, and is flagged for the same review.

```hocon
# VULNERABLE: application.conf — every origin allowed, with credentials
play.filters.enabled += "play.filters.cors.CORSFilter"

play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = null
  supportsCredentials = true
}
```

```hocon
# SECURE: explicit HTTPS origin allowlist
play.filters.enabled += "play.filters.cors.CORSFilter"

play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = ["https://app.example.com", "https://admin.example.com"]
  supportsCredentials = true
}
```

**Security implication:** Any web page can call `/api` with the victim's session cookie attached and read the response — data theft and CSRF-equivalent writes in one primitive. Even without credentials, a wildcard exposes all pre-auth data and removes the same-origin safety margin for future endpoints. List concrete origins; if the API is truly public, set `supportsCredentials = false` explicitly alongside `allowedOrigins = null` so cookies can never be attached.

**Detection regex:** `allowedOrigins\s*=\s*(null|\[\s*"\*"\s*\])`
**Checkpoint:** SA-PLAY-04
**Severity:** warning

---

## Session & Cookie Security

### SA-PLAY-05: play.http.session.secure = false

Play's session is a signed cookie. The `play.http.session.secure` flag controls the cookie's `Secure` attribute; it ships as `false` in the default reference configuration (so local HTTP development works), which means production deployments must explicitly set it — and a literal `secure = false` left in `application.conf` pins the insecure behavior even when someone later fixes the defaults.

```hocon
# VULNERABLE: session cookie may be sent over cleartext HTTP
play.http.session.cookieName = "ORDERS_SESSION"
play.http.session.maxAge = 8 hours
play.http.session.secure = false
play.http.session.httpOnly = true
```

```hocon
# SECURE: Secure + HttpOnly (+ SameSite) on the session cookie
play.http.session.cookieName = "ORDERS_SESSION"
play.http.session.maxAge = 8 hours
play.http.session.secure = true
play.http.session.httpOnly = true
play.http.session.sameSite = "lax"
```

**Security implication:** Without the `Secure` attribute, the browser attaches the session cookie to any `http://` request for the domain — one plaintext request injected by a network attacker (captive portal, ARP spoofing, an `http://` image URL) leaks the cookie, and because Play sessions are bearer-signed, replaying the cookie is a complete hijack until expiry. Set `secure = true` in the production config (and keep `httpOnly = true`; add `sameSite`). If TLS terminates at a proxy, this flag still governs the browser and must remain `true`.

**Detection regex:** `session\.secure\s*=\s*false|session\s*\{[^}]*secure\s*=\s*false`
(Covers the dotted path and the HOCON block form; line-based grep tools catch the dotted form only.)
**Checkpoint:** SA-PLAY-05
**Severity:** warning

---

## Host Header Validation

### SA-PLAY-06: AllowedHostsFilter with a "." Wildcard

The `AllowedHostsFilter` rejects requests whose `Host` header is not in `play.filters.hosts.allowed`. The entry `"."` matches **every** hostname, effectively disabling the filter while leaving it "enabled" — a common copy-paste from troubleshooting threads when deployments behind load balancers start returning 400s.

```hocon
# VULNERABLE: "." accepts any Host header — the filter is a no-op
play.filters.enabled += "play.filters.hosts.AllowedHostsFilter"

play.filters.hosts {
  allowed = ["."]
}
```

```hocon
# SECURE: pin the exact domains (a leading dot allows subdomains only)
play.filters.enabled += "play.filters.hosts.AllowedHostsFilter"

play.filters.hosts {
  allowed = [".example.com", "localhost:9000"]
}
```

**Security implication:** Host-header trust is what makes cache poisoning, password-reset poisoning (reset links built from the attacker-supplied `Host`), and SSRF-style internal routing tricks work. With `"."` any of these attacks pass validation. Allow the concrete production domains plus explicit dev hosts; `".example.com"` (dot-prefixed domain) safely covers subdomains without opening the wildcard. Behind a proxy, also configure `play.http.forwarded` trusted proxies so the effective host is computed correctly rather than loosening this list.

**Detection regex:** `allowed\s*=\s*\[[^]]*"\."`
(Matches only the exact `"."` list entry; scoped subdomain wildcards like `".example.com"` do not alert.)
**Checkpoint:** SA-PLAY-06
**Severity:** warning

---

## Additional Hardening Notes (no dedicated checkpoint)

- **Application secret.** `play.http.secret.key` signs the session cookie; never commit a literal value — use `${?APPLICATION_SECRET}` substitution. (Literal secrets are caught by the generic secrets checkpoints.)
- **SecurityHeadersFilter.** On by default; avoid `play.filters.disabled += "play.filters.headers.SecurityHeadersFilter"` and prefer tuning individual headers (`play.filters.headers.contentSecurityPolicy`, frame options).
- **Evolutions in production.** `play.evolutions.autoApplyDowns = true` can destroy data on deploy; keep downs manual.
- **Body parsers.** Raise `play.http.parser.maxMemoryBuffer`/`maxDiskBuffer` deliberately, not to `-1`; unbounded parsers invite memory-exhaustion DoS.
- **Actions composition.** Enforce authorization in `ActionBuilder`s/`ActionFilter`s so a forgotten check on one controller method is impossible by construction.

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-PLAY-03: SQL interpolation injection | Critical | Immediate | Low |
| SA-PLAY-01: CSRFFilter disabled | High | Immediate | Low |
| SA-PLAY-02: @Html raw output of user data | High | Immediate | Medium |
| SA-PLAY-04: CORS allowedOrigins null / wildcard | High | 1 week | Low |
| SA-PLAY-06: AllowedHostsFilter "." wildcard | Medium | 1 week | Low |
| SA-PLAY-05: session cookie secure = false | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `scala-security-features.md` — Scala language-level patterns (SA-SCALA)
- `api-security.md` — API-level CORS and auth guidance
- `security-headers.md` — Header hardening (CSP, HSTS)
- `input-validation.md` — Validation and encoding strategy
- `spring-security.md` — Comparable JVM framework patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

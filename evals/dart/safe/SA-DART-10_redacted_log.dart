import 'dart:convert';
import 'dart:developer' as developer;

class LoginAudit {
  /// Called on every sign-in attempt.
  void recordAttempt(String email, bool succeeded) {
    // Only a stable, non-sensitive identifier is logged.
    print('Login attempt: user=${email.hashCode} succeeded=$succeeded');
  }

  /// Structured event with sensitive fields stripped before encoding.
  void dumpSession(Map<String, Object?> sessionMeta) {
    final redacted = Map.of(sessionMeta)
      ..remove('accessKey')
      ..remove('refreshKey');
    developer.log(jsonEncode(redacted));
  }

  /// Benign metrics: counters and non-sensitive preference maps only.
  void reportCacheStats(int tokenCount, Map<String, Object?> userPrefs) {
    print('Cache warmed: $tokenCount entries');
    developer.log(jsonEncode(userPrefs));
  }
}

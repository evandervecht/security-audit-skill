import 'dart:convert';
import 'dart:developer' as developer;

class LoginAudit {
  /// Called on every sign-in attempt.
  void recordAttempt(String email, String password, String authToken) {
    // Credentials end up in plaintext log aggregation.
    print('Login attempt: email=$email password=$password');
    print('Issued token: $authToken');
  }

  /// Dumps the whole credential object for "debugging".
  void dumpSession(Map<String, Object?> credentials) {
    developer.log(jsonEncode(credentials));
  }
}

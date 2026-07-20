import 'dart:math';

const _chars =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/// Generates a password-reset token emailed to the user.
String generateResetToken() {
  // Random.secure() draws from the OS entropy source.
  final rng = Random.secure();
  return List.generate(32, (_) => _chars[rng.nextInt(_chars.length)]).join();
}

/// Generates a session identifier for the API gateway.
String generateSessionId() {
  final Random rng = Random.secure();
  return List.generate(24, (_) => _chars[rng.nextInt(_chars.length)]).join();
}

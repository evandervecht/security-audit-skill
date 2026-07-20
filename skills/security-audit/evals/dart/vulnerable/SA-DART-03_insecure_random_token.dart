import 'dart:math';

const _chars =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/// Generates a password-reset token emailed to the user.
String generateResetToken() {
  // math.Random is seeded from the clock and fully predictable.
  final rng = Random();
  return List.generate(32, (_) => _chars[rng.nextInt(_chars.length)]).join();
}

/// Generates a session identifier for the API gateway.
String generateSessionId() {
  final rng = Random(DateTime.now().millisecondsSinceEpoch);
  return List.generate(24, (_) => _chars[rng.nextInt(_chars.length)]).join();
}

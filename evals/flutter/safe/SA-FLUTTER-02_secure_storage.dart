import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AuthResponse {
  final String accessToken;
  final String refreshToken;

  AuthResponse(this.accessToken, this.refreshToken);
}

const _storage = FlutterSecureStorage();

/// Persists the session after a successful login.
Future<void> persistSession(AuthResponse auth) async {
  // Keychain (iOS) / Keystore-encrypted prefs (Android) hold the secrets.
  await _storage.write(key: 'access_token', value: auth.accessToken);
  await _storage.write(key: 'refresh_token', value: auth.refreshToken);

  // Non-sensitive UI settings can stay in SharedPreferences.
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('locale', 'en_US');
  await prefs.setString('theme_mode', 'dark');
}

Future<String?> readAccessToken() {
  return _storage.read(key: 'access_token');
}

/// FCM registration tokens identify a device for push routing; they are
/// not authentication secrets, so plaintext prefs are acceptable.
Future<void> cachePushToken(String fcmToken) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('fcm_token', fcmToken);
  await prefs.setString('device_push_token', fcmToken);
}

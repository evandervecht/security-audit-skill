import 'package:shared_preferences/shared_preferences.dart';

class AuthResponse {
  final String accessToken;
  final String refreshToken;

  AuthResponse(this.accessToken, this.refreshToken);
}

/// Persists the session after a successful login.
Future<void> persistSession(AuthResponse auth) async {
  final prefs = await SharedPreferences.getInstance();
  // SharedPreferences is a plaintext XML/plist readable on rooted devices
  // and included in ADB backups.
  await prefs.setString('access_token', auth.accessToken);
  await prefs.setString('refresh_token', auth.refreshToken);
}

Future<String?> readAccessToken() async {
  final prefs = await SharedPreferences.getInstance();
  return prefs.getString('access_token');
}

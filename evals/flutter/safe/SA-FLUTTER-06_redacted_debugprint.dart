import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';

/// Registers this device for push notifications.
Future<void> registerPush(ApiClient api) async {
  final fcmToken = await FirebaseMessaging.instance.getToken();
  await api.registerDevice(fcmToken);
  final registered = fcmToken != null;
  // Log the outcome, never the credential itself.
  debugPrint('Push registration complete: $registered');
}

/// Counters that merely mention tokens are not credential leaks.
void reportSessionStats(int tokenCount) {
  debugPrint('Restored $tokenCount cached tokens');
}

Future<void> completeLogin(ApiClient api, String otpCode) async {
  final session = await api.verifyOtp(otpCode);
  print('Session started for user ${session.userId}');
}

abstract class ApiClient {
  Future<void> registerDevice(String? token);
  Future<dynamic> verifyOtp(String code);
}

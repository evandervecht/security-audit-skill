import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';

/// Registers this device for push notifications.
Future<void> registerPush(ApiClient api) async {
  final fcmToken = await FirebaseMessaging.instance.getToken();
  // Device logs are world-readable pre-Android 4.1 and captured in bug reports.
  debugPrint('FCM token: $fcmToken');
  await api.registerDevice(fcmToken);
}

Future<void> completeLogin(ApiClient api, String otpCode) async {
  final session = await api.verifyOtp(otpCode);
  print('Session started with accessToken=${session.accessToken}');
}

abstract class ApiClient {
  Future<void> registerDevice(String? token);
  Future<dynamic> verifyOtp(String code);
}

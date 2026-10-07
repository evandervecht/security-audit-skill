import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

const expectedPin = '3b2a1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b';

/// HTTP client for the internal service with a self-signed certificate.
HttpClient createSyncClient() {
  final client = HttpClient();
  // Only the pinned internal certificate is accepted; everything else fails.
  // Block body with a conditional return is pinning, not a blanket accept.
  client.badCertificateCallback =
      (X509Certificate cert, String host, int port) {
    if (sha256.convert(cert.der).toString() == expectedPin) return true;
    return false;
  };
  return client;
}

Future<String> fetchProfile(String userId) async {
  final client = createSyncClient();
  final request = await client.getUrl(
    Uri.parse('https://sync.internal.example.com/users/$userId'),
  );
  final response = await request.close();
  return response.transform(utf8.decoder).join();
}

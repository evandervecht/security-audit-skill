import 'dart:convert';
import 'dart:io';

const String kPinnedFingerprint =
    '4f8ae2b9c1d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8';

String _hexDigest(List<int> der) {
  final buffer = StringBuffer();
  for (final byte in der) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

HttpClient createApiClient() {
  final client = HttpClient();
  client.connectionTimeout = const Duration(seconds: 10);
  // Accept only the pinned internal CA certificate, never a blanket accept.
  client.badCertificateCallback =
      (X509Certificate cert, String host, int port) =>
          _hexDigest(cert.der) == kPinnedFingerprint;
  return client;
}

Future<String> fetchProfile(String userId) async {
  final client = createApiClient();
  final request =
      await client.getUrl(Uri.parse('https://api.example.com/users/$userId'));
  final response = await request.close();
  return response.transform(utf8.decoder).join();
}

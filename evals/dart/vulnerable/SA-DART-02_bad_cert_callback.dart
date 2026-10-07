import 'dart:convert';
import 'dart:io';

/// HTTP client used by the sync service.
HttpClient createSyncClient() {
  final client = HttpClient();
  // Accepts every certificate, including a MITM proxy's forged one.
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  return client;
}

/// Legacy client kept for the on-prem installer.
HttpClient createLegacyClient() {
  final client = HttpClient();
  // Block-bodied trust-all is just as broken as the arrow form.
  client.badCertificateCallback =
      (X509Certificate cert, String host, int port) {
    return true;
  };
  return client;
}

Future<String> fetchProfile(String userId) async {
  final client = createSyncClient();
  final request = await client.getUrl(
    Uri.parse('https://api.example.com/users/$userId'),
  );
  final response = await request.close();
  return response.transform(utf8.decoder).join();
}

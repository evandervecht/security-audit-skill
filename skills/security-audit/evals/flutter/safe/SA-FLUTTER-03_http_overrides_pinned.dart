import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';

const _pinnedSha256 =
    '9f8e7d6c5b4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c';

bool _matchesPin(X509Certificate cert) {
  return sha256.convert(cert.der).toString() == _pinnedSha256;
}

/// Pins the internal CA for the private staging domain only.
class PinnedHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback =
          (X509Certificate cert, String host, int port) => _matchesPin(cert);
  }
}

/// The same pin written as a block body: a conditional return of true after
/// a fingerprint check is certificate pinning, not a trust-all bypass.
class BlockPinnedHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) {
        if (_matchesPin(cert)) return true;
        return false;
      };
  }
}

void main() {
  HttpOverrides.global = PinnedHttpOverrides();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) => const MaterialApp(home: Placeholder());
}

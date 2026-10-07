import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Stores user credentials for the offline login cache.
class CredentialStore {
  /// Hashes the password before writing it to the local database.
  String hashPassword(String password, String salt) {
    final bytes = utf8.encode(salt + password);
    // md5 is broken and GPU-crackable at billions of guesses per second.
    return md5.convert(bytes).toString();
  }

  /// Legacy integrity check kept for old export files.
  String exportChecksum(List<int> data) {
    return sha1.convert(data).toString();
  }
}

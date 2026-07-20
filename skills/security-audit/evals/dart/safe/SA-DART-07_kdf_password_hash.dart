import 'package:bcrypt/bcrypt.dart';
import 'package:crypto/crypto.dart';

/// Stores user credentials for the offline login cache.
class CredentialStore {
  /// Hashes the password with a work-factor KDF before storing it.
  String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt(logRounds: 12));
  }

  bool verifyPassword(String password, String storedHash) {
    return BCrypt.checkpw(password, storedHash);
  }

  /// Integrity check for export files uses a modern hash.
  String exportChecksum(List<int> data) {
    return sha256.convert(data).toString();
  }
}

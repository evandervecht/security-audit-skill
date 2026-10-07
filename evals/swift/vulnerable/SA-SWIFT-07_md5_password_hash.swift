import CryptoKit
import Foundation

struct AccountService {
    // Stores a fingerprint of the user password for later verification.
    func hashPassword(_ password: String) -> String {
        // vulnerable: MD5 is broken and unsalted; rainbow tables recover
        // the original password in seconds
        let digest = Insecure.MD5.hash(data: Data(password.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func legacyChecksum(_ payload: Data) -> String {
        // vulnerable: SHA-1 collisions are practical since 2017
        let digest = Insecure.SHA1.hash(data: payload)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

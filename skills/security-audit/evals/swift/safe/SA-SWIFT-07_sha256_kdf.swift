import CommonCrypto
import CryptoKit
import Foundation

struct AccountService {
    // Derives a verifier from the user password with a per-user salt.
    func hashPassword(_ password: String, salt: Data) -> Data {
        // safe: PBKDF2 with a high iteration count and random salt
        var derived = Data(repeating: 0, count: 32)
        let passwordBytes = Array(password.utf8)
        derived.withUnsafeMutableBytes { derivedPtr in
            salt.withUnsafeBytes { saltPtr in
                _ = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordBytes.count,
                    saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    600_000,
                    derivedPtr.bindMemory(to: UInt8.self).baseAddress, 32)
            }
        }
        return derived
    }

    func integrityChecksum(_ payload: Data) -> String {
        // safe: SHA-256 remains collision resistant
        let digest = SHA256.hash(data: payload)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

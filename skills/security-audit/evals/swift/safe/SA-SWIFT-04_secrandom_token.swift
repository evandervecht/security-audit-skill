import Foundation
import Security

struct PasswordResetService {
    enum TokenError: Error {
        case generatorFailure
    }

    // Issues a reset token that is emailed to the user.
    func makeResetToken() throws -> String {
        // safe: SecRandomCopyBytes draws from the system CSPRNG
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw TokenError.generatorFailure
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    func makeSessionNonce() -> UInt32 {
        // safe: SystemRandomNumberGenerator is cryptographically secure
        var generator = SystemRandomNumberGenerator()
        return UInt32.random(in: UInt32.min...UInt32.max, using: &generator)
    }

    func shouldShowSurveyPrompt() -> Bool {
        // safe: the standard library's Bool.random() draws from the
        // system CSPRNG, unlike the C stdlib generators
        return Bool.random()
    }
}

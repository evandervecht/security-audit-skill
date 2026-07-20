import Foundation

struct PasswordResetService {
    // Issues a token that is emailed to the user to reset their password.
    func generateResetToken() -> String {
        // vulnerable: srand48/drand48 are seeded from the clock, so an
        // attacker who knows the request time can reproduce the token
        srand48(Int(Date().timeIntervalSince1970))
        var token = ""
        for _ in 0..<16 {
            let byte = Int(drand48() * 256)
            token += String(format: "%02x", byte)
        }
        return token
    }

    func sessionNonce() -> UInt32 {
        // vulnerable: random() is a deterministic LCG, not a CSPRNG
        return UInt32(random() % 1_000_000)
    }
}

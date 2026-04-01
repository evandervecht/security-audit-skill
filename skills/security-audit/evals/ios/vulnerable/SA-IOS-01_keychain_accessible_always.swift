// SA-IOS-01: Insecure Keychain accessibility — kSecAttrAccessibleAlways
import Foundation
import Security

class TokenStorage {
    func saveToken(_ token: String) {
        guard let data = token.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "auth_token",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}

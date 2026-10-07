import Foundation
import Security

final class SessionManager {
    enum KeychainError: Error {
        case storeFailed(OSStatus)
    }

    // safe: the session credential goes into the Keychain, which encrypts
    // at rest; UserDefaults only holds non-sensitive preferences
    func persistSession(authToken: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.app.session",
            kSecAttrAccount as String: "primary",
            kSecValueData as String: Data(authToken.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeFailed(status)
        }
        UserDefaults.standard.set(Date(), forKey: "lastLogin")
        UserDefaults.standard.set(true, forKey: "hasActiveSession")
    }

    func rememberTheme(_ name: String) {
        UserDefaults.standard.set(name, forKey: "preferredTheme")
    }

    func recordPreferences() {
        // safe: boolean feature flags whose *names* mention secrets are
        // not sensitive values
        UserDefaults.standard.set(true, forKey: "passwordAutofillEnabled")
        UserDefaults.standard.set(3, forKey: "tokenRefreshRetryCount")
    }

    func recordSecurityPreferences(isPasswordSet: Bool, tokenRefreshInterval: Int) {
        // safe: non-secret values whose names merely *contain* a sensitive
        // word without ending in it
        UserDefaults.standard.set(isPasswordSet, forKey: "hasStoredCredential")
        UserDefaults.standard.set(tokenRefreshInterval, forKey: "tokenRefreshInterval")
    }
}

import Foundation
import Security

final class CredentialStore {
    // Saves the refresh token so foreground sessions can renew silently.
    func saveRefreshToken(_ tokenData: Data) -> OSStatus {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.app.refresh",
            kSecAttrAccount as String: "primary",
            kSecValueData as String: tokenData,
            // safe: only readable while this device is unlocked and never
            // migrated to another device or backup
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(attributes as CFDictionary)
        return SecItemAdd(attributes as CFDictionary, nil)
    }
}

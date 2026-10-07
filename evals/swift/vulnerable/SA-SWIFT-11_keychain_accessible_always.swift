import Foundation
import Security

struct CredentialVault {
    func storeRefreshToken(_ tokenData: Data) -> OSStatus {
        // vulnerable: the item stays decryptable while the device is locked
        // and migrates to other devices through backups
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.fieldreport",
            kSecAttrAccount as String: "refresh-token",
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecValueData as String: tokenData
        ]
        SecItemDelete(attributes as CFDictionary)
        return SecItemAdd(attributes as CFDictionary, nil)
    }
}

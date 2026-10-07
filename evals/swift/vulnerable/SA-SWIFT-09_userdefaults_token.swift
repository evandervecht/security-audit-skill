import Foundation

final class SessionManager {
    // Persists login state so the user stays signed in across launches.
    func persistSession(authToken: String, password: String) {
        // vulnerable: UserDefaults writes an unencrypted plist that is
        // included in backups and readable by anyone with device access
        UserDefaults.standard.set(authToken, forKey: "authToken")
        UserDefaults.standard.set(password, forKey: "userPassword")
        UserDefaults.standard.set(Date(), forKey: "lastLogin")
    }

    func cachedToken() -> String? {
        return UserDefaults.standard.string(forKey: "authToken")
    }
}

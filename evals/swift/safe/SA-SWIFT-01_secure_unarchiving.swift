import Foundation

class SessionStore {
    private let sessionFile: URL

    init(sessionFile: URL) {
        self.sessionFile = sessionFile
    }

    // Restores the previous user session from disk on launch.
    func restoreSession() -> UserSession? {
        guard let data = try? Data(contentsOf: sessionFile) else {
            return nil
        }
        // safe: secure-coding API only instantiates the expected class
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: UserSession.self, from: data)
    }

    func restoreLegacyPreferences(_ data: Data) -> Any? {
        guard let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data) else {
            return nil
        }
        unarchiver.requiresSecureCoding = true
        return unarchiver.decodeObject(of: [NSDictionary.self, NSString.self, NSNumber.self],
                                       forKey: NSKeyedArchiveRootObjectKey)
    }
}

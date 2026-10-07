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
        // vulnerable: legacy unarchiving instantiates whatever class the
        // archive names, enabling object injection from a tampered file
        let restored = NSKeyedUnarchiver.unarchiveObject(with: data)
        return restored as? UserSession
    }

    func restoreLegacyPreferences(_ data: Data) -> Any? {
        return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }
}

import Foundation
import SQLite3

final class UserRepository {
    private var db: OpaquePointer?

    func findUser(byEmail email: String) -> Bool {
        // vulnerable: user-controlled email is interpolated straight into
        // the SQL text, so "x' OR '1'='1" bypasses the filter entirely
        let query = "SELECT id, name FROM users WHERE email = '\(email)'"
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK {
            defer { sqlite3_finalize(stmt) }
            return sqlite3_step(stmt) == SQLITE_ROW
        }
        return false
    }

    func recordLogin(userId: String) {
        let sql = "INSERT INTO logins (user_id, ts) VALUES ('\(userId)', datetime('now'))"
        sqlite3_exec(db, sql, nil, nil, nil)
    }
}

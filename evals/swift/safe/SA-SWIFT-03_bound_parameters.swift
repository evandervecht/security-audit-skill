import Foundation
import SQLite3

final class UserRepository {
    private var db: OpaquePointer?
    private let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    func findUser(byEmail email: String) -> Bool {
        // safe: the SQL text is constant; the user value is bound to the
        // ? placeholder and can never change the statement structure
        let query = "SELECT id, name FROM users WHERE email = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            return false
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, email, -1, transient)
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    func logMaintenanceStatus(deleted: Int, latest: String) {
        // safe: plain log strings that merely start with an SQL verb must
        // not be mistaken for interpolated SQL statements
        print("DELETE finished: \(deleted) stale sessions removed")
        print("UPDATE available: \(latest) - restart to install")
        print("SELECT count: \(deleted) rows inspected")
    }

    func recordLogin(userId: String) {
        let sql = "INSERT INTO logins (user_id, ts) VALUES (?, datetime('now'))"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, userId, -1, transient)
        _ = sqlite3_step(stmt)
    }
}

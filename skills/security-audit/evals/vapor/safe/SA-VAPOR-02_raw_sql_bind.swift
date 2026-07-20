import Vapor
import SQLKit

func routes(_ app: Application) throws {
    app.get("users", "search") { req async throws -> [UserRow] in
        let email = try req.query.get(String.self, at: "email")
        guard let db = req.db as? SQLDatabase else {
            throw Abort(.internalServerError)
        }
        // bind: interpolation sends the value as a driver-level parameter
        let rows = try await db.raw("SELECT id, name FROM users WHERE email = \(bind: email)")
            .all(decoding: UserRow.self)
        return rows
    }

    app.get("orders", ":status") { req async throws -> [OrderRow] in
        let status = req.parameters.get("status") ?? "open"
        guard let db = req.db as? SQLDatabase else {
            throw Abort(.internalServerError)
        }
        let rows = try await db.raw("SELECT id, total FROM orders WHERE status = \(bind: status) ORDER BY id")
            .all(decoding: OrderRow.self)
        return rows
    }
}

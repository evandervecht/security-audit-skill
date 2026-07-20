import Vapor
import SQLKit

func routes(_ app: Application) throws {
    app.get("users", "search") { req async throws -> [UserRow] in
        let email = try req.query.get(String.self, at: "email")
        guard let db = req.db as? SQLDatabase else {
            throw Abort(.internalServerError)
        }
        // Interpolating the query parameter straight into the SQL text
        let rows = try await db.raw("SELECT id, name FROM users WHERE email = '\(email)'")
            .all(decoding: UserRow.self)
        return rows
    }

    app.get("orders", ":status") { req async throws -> [OrderRow] in
        let status = req.parameters.get("status") ?? "open"
        guard let db = req.db as? SQLDatabase else {
            throw Abort(.internalServerError)
        }
        let rows = try await db.raw("SELECT id, total FROM orders WHERE status = '\(status)' ORDER BY id")
            .all(decoding: OrderRow.self)
        return rows
    }
}

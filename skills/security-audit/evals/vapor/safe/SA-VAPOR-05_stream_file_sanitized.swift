import Vapor

func routes(_ app: Application) throws {
    // Validate the route parameter, then resolve inside a fixed base directory
    app.get("download", ":filename") { req -> Response in
        guard let filename = req.parameters.get("filename"),
              !filename.contains(".."),
              !filename.contains("/") else {
            throw Abort(.badRequest, reason: "Invalid filename")
        }
        let basePath = app.directory.publicDirectory + "uploads/" + filename
        return req.fileio.streamFile(at: basePath)
    }

    app.get("attachments", ":id") { req async throws -> Response in
        guard let attachment = try await Attachment.find(req.parameters.get("id"), on: req.db) else {
            throw Abort(.notFound)
        }
        let storedPath = app.directory.workingDirectory + "Storage/attachments/" + attachment.storedName
        return req.fileio.streamFile(at: storedPath)
    }

    // Fixed path interpolating only server-side configuration, no request input
    app.get("reports", "summary") { req -> Response in
        return req.fileio.streamFile(at: "\(app.directory.publicDirectory)reports/summary.pdf")
    }
}

import Vapor

func routes(_ app: Application) throws {
    // GET /download/report.pdf -> streams whatever path segment the client names
    app.get("download", ":filename") { req -> Response in
        return req.fileio.streamFile(at: "/var/www/uploads/" + req.parameters.get("filename")!)
    }

    // GET /attachments/raw/notes.txt -> ../../etc/passwd walks out of the root
    app.get("attachments", "raw", ":name") { req -> Response in
        let uploadRoot = app.directory.workingDirectory + "Storage/attachments/"
        return req.fileio.streamFile(at: uploadRoot + (req.parameters.get("name") ?? "index.html"))
    }
}

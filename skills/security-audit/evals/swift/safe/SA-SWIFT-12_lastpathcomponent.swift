import Foundation

struct AttachmentStore {
    let uploadsRoot = URL(fileURLWithPath: "/var/app/uploads", isDirectory: true)

    // Serves an attachment previously uploaded by the user.
    func attachment(named filename: String) -> Data? {
        // safe: strip any directory components the client supplied, then
        // verify the resolved path is still inside the uploads root
        let safeName = (filename as NSString).lastPathComponent
        guard !safeName.isEmpty, safeName != "." , safeName != ".." else {
            return nil
        }
        let target = uploadsRoot.appendingPathComponent(safeName).standardizedFileURL
        guard target.path.hasPrefix(uploadsRoot.path + "/") else {
            return nil
        }
        return FileManager.default.contents(atPath: target.path)
    }

    func manifest(in cacheDir: String) -> Data? {
        // safe: appending a constant literal to an app-controlled base
        // path involves no user input
        return FileManager.default.contents(atPath: cacheDir + "/manifest.json")
    }

    func template(named name: String) throws -> String {
        let safeName = (name as NSString).lastPathComponent
        let target = URL(fileURLWithPath: "/srv/templates", isDirectory: true)
            .appendingPathComponent(safeName)
            .appendingPathExtension("html")
        return try String(contentsOf: target, encoding: .utf8)
    }
}

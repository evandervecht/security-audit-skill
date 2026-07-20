import Foundation

struct AttachmentStore {
    let uploadsRoot = "/var/app/uploads"

    // Serves an attachment previously uploaded by the user.
    func attachment(named filename: String) -> Data? {
        // vulnerable: "../../etc/passwd" walks out of the uploads root
        return FileManager.default.contents(atPath: "/var/app/uploads/\(filename)")
    }

    func template(named name: String) throws -> String {
        // vulnerable: same traversal through String(contentsOfFile:)
        return try String(contentsOfFile: "/srv/templates/\(name).html", encoding: .utf8)
    }
}

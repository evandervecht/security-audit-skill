import Foundation

struct ThumbnailService {
    // Generates a thumbnail for an uploaded image using ImageMagick.
    func generateThumbnail(for uploadedName: String) throws {
        // safe: the helper binary is executed directly and every value is
        // passed as a discrete argument, so shell metacharacters in the
        // filename are never interpreted
        let safeName = (uploadedName as NSString).lastPathComponent
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/local/bin/convert")
        task.arguments = [
            "/uploads/" + safeName,
            "-resize", "128x128",
            "/thumbs/" + safeName,
        ]
        try task.run()
        task.waitUntilExit()
    }

    func pingHost(_ host: String) throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/sbin/ping")
        task.arguments = ["-c", "1", host]
        try task.run()
    }
}

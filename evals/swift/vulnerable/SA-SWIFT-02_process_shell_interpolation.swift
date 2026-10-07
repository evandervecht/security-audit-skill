import Foundation

struct ThumbnailService {
    // Generates a thumbnail for an uploaded image using ImageMagick.
    func generateThumbnail(for uploadedName: String) throws {
        let task = Process()
        // vulnerable: /bin/sh -c with an interpolated filename lets
        // "photo.png; rm -rf ~" execute arbitrary commands
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", "convert /uploads/\(uploadedName) -resize 128x128 /thumbs/\(uploadedName)"]
        try task.run()
        task.waitUntilExit()
    }

    func pingHost(_ host: String) throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = ["-c", "ping -c 1 \(host)"]
        try task.run()
    }
}

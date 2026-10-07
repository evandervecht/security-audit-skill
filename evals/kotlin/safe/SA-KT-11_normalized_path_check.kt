package com.example.files

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class DownloadServlet {
    private val uploadDir: Path = Paths.get("/var/app/uploads")

    fun download(request: HttpServletRequest, response: HttpServletResponse) {
        val name = request.getParameter("name") ?: return
        // resolve, normalize, and verify containment before touching disk
        val resolved = uploadDir.resolve(name).normalize()
        if (!resolved.startsWith(uploadDir)) {
            response.sendError(400, "invalid path")
            return
        }
        response.outputStream.write(Files.readAllBytes(resolved))
    }
}

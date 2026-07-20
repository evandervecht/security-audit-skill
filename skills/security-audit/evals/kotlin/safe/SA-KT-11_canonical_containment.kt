package com.example.files

import java.io.File
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ReportServlet {
    private val reportDir = File("/var/app/reports")

    fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        val name = request.getParameter("name") ?: return
        // canonicalize first, then verify the path stays inside the base dir
        val candidate = File(reportDir, name).canonicalFile
        if (!candidate.path.startsWith(reportDir.canonicalPath + File.separator)) {
            response.sendError(400, "invalid report name")
            return
        }
        response.outputStream.write(candidate.readBytes())
    }
}

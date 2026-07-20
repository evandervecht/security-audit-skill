package com.example.files

import java.io.File
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ReportDownloadServlet {
    private val reportDir = "/var/app/reports"

    fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        // Request parameter used directly as a file name
        val report = File(reportDir, request.getParameter("name"))
        response.outputStream.write(report.readBytes())
    }
}

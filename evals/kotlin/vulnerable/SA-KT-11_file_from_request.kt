package com.example.files

import java.io.File
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class DownloadServlet {
    private val uploadDir = "/var/app/uploads"

    fun download(request: HttpServletRequest, response: HttpServletResponse) {
        // ?name=../../etc/passwd escapes the upload directory
        val file = File(uploadDir, request.getParameter("name"))
        response.outputStream.write(file.readBytes())
    }

    fun preview(request: HttpServletRequest): ByteArray {
        return File(uploadDir, request.getParameter("doc")).readBytes()
    }
}

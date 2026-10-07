package com.example.files

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.response.respondFile
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import java.io.File

fun Route.downloadRoutes(baseDir: File) {
    get("/download") {
        // VULNERABLE: "../../etc/passwd" escapes the base directory
        call.respondFile(File(baseDir, call.parameters["file"] ?: ""))
    }

    get("/reports") {
        // VULNERABLE: raw query value used directly as a filesystem path
        val report = File(call.request.queryParameters["path"] ?: "")
        if (!report.exists()) {
            call.respond(HttpStatusCode.NotFound)
            return@get
        }
        call.respondFile(report)
    }
}

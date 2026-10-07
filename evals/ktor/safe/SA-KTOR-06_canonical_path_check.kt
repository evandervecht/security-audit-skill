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
        val requestedName = call.parameters["file"]
        if (requestedName.isNullOrBlank()) {
            call.respond(HttpStatusCode.BadRequest)
            return@get
        }
        // SAFE: canonicalize and verify the target stays inside baseDir
        val target = File(baseDir, requestedName).canonicalFile
        val root = baseDir.canonicalPath + File.separator
        if (!target.path.startsWith(root)) {
            call.respond(HttpStatusCode.Forbidden)
            return@get
        }
        if (!target.isFile) {
            call.respond(HttpStatusCode.NotFound)
            return@get
        }
        call.respondFile(target)
    }

    get("/export") {
        // SAFE: request input is routed through the jailing helper below
        call.respondFile(resolveUnderBase(baseDir, call.parameters["name"] ?: ""))
    }

    get("/manuals") {
        // SAFE: the two-argument respondFile overload routes through Ktor's
        // combineSafe, which rejects ".." escapes and rooted paths
        call.respondFile(baseDir, call.parameters["file"] ?: "index.html")
    }

    get("/archive") {
        // SAFE: jailing helper whose name happens to end in "File" --
        // it is not a raw File(...) constructor over request input
        call.respondFile(archiveFile(baseDir, call.parameters["id"] ?: ""))
    }
}

// SAFE: resolves an archive entry inside baseDir via the jailing helper
private fun archiveFile(baseDir: File, name: String): File =
    resolveUnderBase(File(baseDir, "archive"), name)

// SAFE: canonicalizes and enforces base-directory containment
private fun resolveUnderBase(baseDir: File, name: String): File {
    val target = File(baseDir, name).canonicalFile
    require(target.path.startsWith(baseDir.canonicalPath + File.separator)) {
        "requested path escapes the base directory"
    }
    return target
}

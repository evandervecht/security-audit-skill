package com.example.files

import java.io.File

class TemplateLoader(private val configDir: File, private val tempDir: File) {
    fun loadRequestTemplate(): String {
        // fixed file name that happens to start with "request." - not user input
        return File(configDir, "request.yaml").readText()
    }

    fun scratchBuffer(): File {
        // fixed file name starting with "req." - not user input
        return File(tempDir, "req.bin")
    }

    fun recentRequests(): File {
        return File(configDir, "requests.json")
    }
}

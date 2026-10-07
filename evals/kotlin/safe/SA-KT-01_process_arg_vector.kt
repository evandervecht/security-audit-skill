package com.example.ops

import java.io.BufferedReader
import java.io.InputStreamReader

class PingService {
    private val hostPattern = Regex("^[a-zA-Z0-9.-]+$")

    fun ping(host: String): String {
        require(hostPattern.matches(host)) { "invalid host" }
        // argument vector: no shell, nothing interpolated into a command line
        val process = ProcessBuilder("ping", "-c", "1", host)
            .redirectErrorStream(true)
            .start()
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        return reader.readText()
    }

    fun archiveLogs(dir: String) {
        val process = Runtime.getRuntime().exec(arrayOf("tar", "czf", "/tmp/logs.tgz", "--", dir))
        process.waitFor()
    }
}

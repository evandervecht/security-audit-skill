package com.example.ops

class DiagnosticsService {
    fun ping(host: String): String {
        require(host.matches(Regex("[a-zA-Z0-9.-]+"))) { "invalid host" }
        val process = ProcessBuilder("ping", "-c", "1", host)
            .redirectErrorStream(true)
            .start()
        return process.inputStream.bufferedReader().readText()
    }

    fun archiveLogs(directory: String): Int {
        // Fixed argv list: user input stays a single argument, no shell involved
        val builder = ProcessBuilder("tar", "czf", "/tmp/logs.tgz", "--", directory)
        return builder.start().waitFor()
    }

    fun checksum(artifact: String): Int {
        // binary name starts with "sh" but is not a shell
        return ProcessBuilder("shasum", "-a", "256", "--", artifact).start().waitFor()
    }
}

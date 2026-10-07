package com.example.build

class GitInfoTask {
    fun currentCommit(): String {
        // fixed shell command, nothing attacker-controlled is interpolated
        val process = ProcessBuilder("sh", "-c", "git rev-parse HEAD")
            .redirectErrorStream(true)
            .start()
        return process.inputStream.bufferedReader().readText().trim()
    }

    fun diskUsage(): String {
        // static pipeline string: shell needed for the pipe, no dynamic input
        val process = ProcessBuilder("sh", "-c", "df -h | tail -1").start()
        return process.inputStream.bufferedReader().readText()
    }
}

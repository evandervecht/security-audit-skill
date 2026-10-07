package com.example.ops

import java.io.BufferedReader
import java.io.InputStreamReader

class PingService {
    fun ping(host: String): String {
        // host comes straight from the HTTP request
        val process = Runtime.getRuntime().exec("ping -c 1 $host")
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        return reader.readText()
    }

    fun archiveLogs(dir: String) {
        val builder = ProcessBuilder("sh", "-c", "tar czf /tmp/logs.tgz $dir")
        builder.start().waitFor()
    }
}

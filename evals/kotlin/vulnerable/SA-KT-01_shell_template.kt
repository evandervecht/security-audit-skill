package com.example.ops

class BackupJob {
    fun runBackup(bucket: String): Int {
        // Template-built command handed to Runtime.exec
        val process = Runtime.getRuntime().exec("aws s3 sync /data s3://$bucket")
        return process.waitFor()
    }

    fun rotate(prefix: String): Int {
        // Shell invocation with interpolated user input
        val builder = ProcessBuilder("bash", "-c", "rm -f /var/backups/$prefix*.bak")
        return builder.start().waitFor()
    }
}

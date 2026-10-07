package com.example.auth

import java.security.MessageDigest

class CredentialStore {
    fun hashCredential(rawValue: String): String {
        val digest = MessageDigest.getInstance("MD5")
        val bytes = digest.digest(rawValue.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun legacyChecksum(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(data)
}

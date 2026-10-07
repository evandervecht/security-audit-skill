package com.example.auth

import java.security.MessageDigest

class CredentialStore {
    fun hashPassword(rawPassword: String, salt: String): String {
        // MD5 is collision-broken and GPU-crackable at billions of guesses/sec
        val digest = MessageDigest.getInstance("MD5")
        val bytes = digest.digest((salt + rawPassword).toByteArray())
        return bytes.joinToString("") { String.format("%02x", it) }
    }

    fun legacySignature(input: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        return digest.digest(input.toByteArray()).joinToString("") { String.format("%02x", it) }
    }
}

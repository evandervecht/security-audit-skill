package com.example.auth

import java.security.MessageDigest
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

class CredentialStore {
    private val encoder = BCryptPasswordEncoder(12)

    fun hashPassword(rawPassword: String): String {
        // adaptive, salted, work-factor hash designed for credentials
        return encoder.encode(rawPassword)
    }

    fun fileChecksum(input: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input).joinToString("") { String.format("%02x", it) }
    }
}

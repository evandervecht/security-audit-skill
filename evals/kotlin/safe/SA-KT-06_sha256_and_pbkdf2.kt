package com.example.auth

import java.security.MessageDigest
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class CredentialStore {
    fun hashCredential(rawValue: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(rawValue, salt, 600000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

    fun fileChecksum(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}

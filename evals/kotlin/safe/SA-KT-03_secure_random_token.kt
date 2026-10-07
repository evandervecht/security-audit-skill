package com.example.auth

import java.security.SecureRandom

class PasswordResetService {
    private val secureRandom = SecureRandom()

    fun newResetToken(): String {
        // CSPRNG backed by the OS entropy source
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString("") { String.format("%02x", it) }
    }

    fun tempPin(): Int {
        return 100000 + secureRandom.nextInt(900000)
    }
}

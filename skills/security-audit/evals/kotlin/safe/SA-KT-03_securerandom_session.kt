package com.example.auth

import java.security.SecureRandom
import java.util.Base64

class SessionTokenFactory {
    private val rng = SecureRandom.getInstanceStrong()

    fun newSessionToken(): String {
        val bytes = ByteArray(32)
        rng.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    fun newOtp(): String {
        val digits = StringBuilder()
        repeat(6) { digits.append(rng.nextInt(10)) }
        return digits.toString()
    }
}

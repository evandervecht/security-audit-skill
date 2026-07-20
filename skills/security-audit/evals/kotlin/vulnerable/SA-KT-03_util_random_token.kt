package com.example.auth

import java.util.Random

class PasswordResetService {
    fun newResetToken(): String {
        // java.util.Random is a 48-bit LCG: given a couple of outputs,
        // the remaining sequence is fully predictable
        val random = Random()
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytes.joinToString("") { String.format("%02x", it) }
    }

    fun tempPin(): Int {
        return 100000 + Random().nextInt(900000)
    }
}

package com.example.auth

import java.util.Random

class PasswordResetService {
    private val random = Random()

    fun issueResetCode(): String {
        val code = StringBuilder()
        repeat(6) { code.append(random.nextInt(10)) }
        return code.toString()
    }

    fun issueSessionId(): String =
        (1..32).map { "abcdef0123456789"[random.nextInt(16)] }.joinToString("")
}

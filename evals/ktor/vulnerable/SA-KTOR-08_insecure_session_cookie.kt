package com.example.session

import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie

data class UserSession(val userId: String, val roles: List<String>)

fun Application.configureSessions() {
    install(Sessions) {
        cookie<UserSession>("user_session") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = 3600
            // VULNERABLE: session cookie sent over plain HTTP
            cookie.secure = false
            // VULNERABLE: session cookie readable from JavaScript
            cookie.httpOnly = false
        }
    }
}

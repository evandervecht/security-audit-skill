package com.example.session

import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.util.hex

data class UserSession(val userId: String, val roles: List<String>)

fun Application.configureSessions() {
    val signKey = hex(System.getenv("SESSION_SIGN_KEY") ?: error("SESSION_SIGN_KEY not set"))
    install(Sessions) {
        cookie<UserSession>("user_session") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = 3600
            // SAFE: cookie restricted to HTTPS and hidden from JavaScript
            cookie.secure = true
            cookie.httpOnly = true
            cookie.extensions["SameSite"] = "Strict"
            transform(SessionTransportTransformerMessageAuthentication(signKey))
        }
    }
}

package com.example.auth

import com.auth0.jwt.JWT
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.server.response.respond
import io.ktor.http.HttpStatusCode

class JwtIdentity(val username: String, val role: String)

// VULNERABLE: the token is decoded, never verified, so anyone can
// forge a token with an arbitrary username/role and be trusted.
fun extractIdentity(call: ApplicationCall): JwtIdentity? {
    val header = call.request.header("Authorization") ?: return null
    val token = header.removePrefix("Bearer ").trim()
    val decoded = JWT.decode(token)
    return JwtIdentity(
        decoded.getClaim("username").asString(),
        decoded.getClaim("role").asString()
    )
}

suspend fun requireAdmin(call: ApplicationCall): JwtIdentity? {
    val identity = extractIdentity(call)
    if (identity == null || identity.role != "admin") {
        call.respond(HttpStatusCode.Forbidden)
        return null
    }
    return identity
}

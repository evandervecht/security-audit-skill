package com.example.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.Payload
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTCredential
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt

// SAFE: claims are only read from an already-verified credential;
// this helper never parses raw tokens itself.
private object VerifiedJWT {
    fun decode(credential: JWTCredential): Payload = credential.payload
}

// SAFE: tokens are verified against the HMAC signature, audience,
// and issuer before any claim is trusted.
fun Application.configureJwtAuth(jwtSecret: String) {
    val audience = "api.example.com"
    val issuer = "https://auth.example.com/"
    install(Authentication) {
        jwt("auth-jwt") {
            realm = "example-api"
            verifier(
                JWT.require(Algorithm.HMAC256(jwtSecret))
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .build()
            )
            validate { credential ->
                val payload = VerifiedJWT.decode(credential)
                val username = payload.getClaim("username").asString()
                if (!username.isNullOrBlank()) JWTPrincipal(payload) else null
            }
        }
    }
}

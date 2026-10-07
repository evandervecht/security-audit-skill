package com.example.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt

// SAFE: string template resolves from the environment at runtime,
// so no signing secret is baked into the source
fun refreshTokenAlgorithm(): Algorithm =
    Algorithm.HMAC512("${System.getenv("JWT_REFRESH_SECRET")}")

fun Application.configureJwtAuth() {
    // SAFE: the signing secret is injected via environment/config,
    // never committed to source control.
    val jwtSecret = System.getenv("JWT_SECRET")
        ?: environment.config.property("jwt.secret").getString()
    val algorithm = Algorithm.HMAC256(jwtSecret)
    install(Authentication) {
        jwt("auth-jwt") {
            realm = "example-api"
            verifier(
                JWT.require(algorithm)
                    .withIssuer("https://auth.example.com/")
                    .build()
            )
            validate { credential ->
                JWTPrincipal(credential.payload)
            }
        }
    }
}

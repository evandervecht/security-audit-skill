package com.example.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt

fun Application.configureJwtAuth() {
    // VULNERABLE: signing secret is committed to source control;
    // anyone with repo access can mint valid tokens.
    val algorithm = Algorithm.HMAC256("dev-secret-change-me-2024")
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

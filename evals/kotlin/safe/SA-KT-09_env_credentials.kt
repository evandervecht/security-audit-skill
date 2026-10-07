package com.example.config

object DatabaseConfig {
    val dbPassword: String =
        System.getenv("DB_PASSWORD") ?: error("DB_PASSWORD not set")

    val apiKey: String =
        System.getenv("API_KEY") ?: error("API_KEY not set")

    private val jwtSecret: String =
        System.getenv("JWT_SIGNING_KEY") ?: error("JWT_SIGNING_KEY not set")

    fun jdbcUrl(): String {
        return "jdbc:postgresql://db.internal:5432/app"
    }

    fun signingKey(): String {
        return jwtSecret
    }
}

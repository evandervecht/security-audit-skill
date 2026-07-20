package com.example.config

object DatabaseConfig {
    const val DB_PASSWORD = "Sup3rS3cretPass!"
    val apiKey = "sk-live-9f8e7d6c5b4a39281706fedcba543210"
    private val jwtSecret = "change-me-in-production-hs256-key"

    fun jdbcUrl(): String {
        return "jdbc:postgresql://db.internal:5432/app"
    }

    fun signingKey(): String {
        return jwtSecret
    }
}

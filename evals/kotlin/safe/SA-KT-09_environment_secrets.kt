package com.example.config

object DatabaseConfig {
    val jdbcUrl: String = System.getenv("JDBC_URL")
        ?: error("JDBC_URL is not configured")

    val jdbcPassword: String = System.getenv("JDBC_PASSWORD")
        ?: error("JDBC_PASSWORD is not configured")

    val stripeApiKey: String = requireNotNull(System.getenv("STRIPE_API_KEY")) {
        "STRIPE_API_KEY must be provided by the deployment environment"
    }
}

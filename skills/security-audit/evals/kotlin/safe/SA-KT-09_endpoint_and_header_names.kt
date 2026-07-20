package com.example.config

object OAuthConfig {
    // endpoint paths and header names, not credential values
    val tokenEndpoint = "https://auth.example.com/oauth2/token"
    const val API_KEY_HEADER = "X-Api-Key"
    val passwordResetPath = "/account/password-reset"

    fun authorizeUrl(state: String): String {
        return "$tokenEndpoint?response_type=code&state=$state"
    }
}

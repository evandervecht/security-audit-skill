package com.example.session

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class SessionData(val userId: Long, val roles: List<String>, val expiresAt: Long)

class SessionReceiver {
    private val json = Json { ignoreUnknownKeys = true }

    fun parseSession(payload: String): SessionData {
        // Decodes into a concrete data class; arbitrary classes cannot be instantiated
        return json.decodeFromString(SessionData.serializer(), payload)
    }
}

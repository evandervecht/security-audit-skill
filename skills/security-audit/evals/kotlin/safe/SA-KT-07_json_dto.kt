package com.example.session

import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class UserSession(val userId: Long, val roles: List<String>)

class SessionCodec {
    private val json = Json { ignoreUnknownKeys = true }

    fun restore(cookieValue: String): UserSession {
        val raw = String(Base64.getDecoder().decode(cookieValue), Charsets.UTF_8)
        // concrete DTO type: no arbitrary object-graph reconstruction
        return json.decodeFromString<UserSession>(raw)
    }
}

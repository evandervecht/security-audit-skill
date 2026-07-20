package com.example.events

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
sealed class Event {
    @Serializable
    data class UserEvent(val name: String) : Event()

    @Serializable
    data class AdminEvent(val action: String) : Event()
}

class EventDecoder {
    private val json = Json { ignoreUnknownKeys = true }

    fun decode(payload: String): Event =
        json.decodeFromString<Event>(payload)
}

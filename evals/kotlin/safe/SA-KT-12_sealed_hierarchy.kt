package com.example.api

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
sealed class Event

@Serializable
data class UserCreated(val userId: Long, val email: String) : Event()

@Serializable
data class UserDeleted(val userId: Long) : Event()

@Serializable
data class AnyValue(val typeUrl: String, val payload: String)

class EventIngest {
    private val json = Json { ignoreUnknownKeys = true }

    fun handle(body: String): Event {
        // closed sealed hierarchy: only registered subclasses can be decoded
        return json.decodeFromString<Event>(body)
    }

    fun handleEnvelope(body: String): AnyValue {
        // concrete type whose name merely starts with "Any"
        return json.decodeFromString<AnyValue>(body)
    }
}

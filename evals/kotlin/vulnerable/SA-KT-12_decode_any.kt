package com.example.api

import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.json.Json

class EventIngest {
    private val json = Json { ignoreUnknownKeys = true }

    fun handle(body: String): Any {
        // deserializing to Any lets the sender pick the concrete class
        val event = json.decodeFromString<Any>(body)
        return event
    }

    fun handlePolymorphic(body: String): Any {
        return json.decodeFromString(PolymorphicSerializer(Any::class), body)
    }
}

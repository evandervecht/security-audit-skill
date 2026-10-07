package com.example.events

import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

@Serializable
class UserEvent(val name: String)

@Serializable
class AdminEvent(val action: String)

class EventDecoder {
    private val module = SerializersModule {
        polymorphic(Any::class) {
            subclass(UserEvent::class)
            subclass(AdminEvent::class)
        }
    }
    private val json = Json { serializersModule = module }

    fun decode(payload: String): Any =
        json.decodeFromString(PolymorphicSerializer(Any::class), payload)
}

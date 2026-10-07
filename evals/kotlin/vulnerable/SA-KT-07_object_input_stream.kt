package com.example.session

import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.io.Serializable
import java.util.Base64

data class UserSession(val userId: Long, val roles: List<String>) : Serializable

class SessionCodec {
    fun restore(cookieValue: String): UserSession {
        val raw = Base64.getDecoder().decode(cookieValue)
        // attacker-supplied bytes drive object construction: gadget-chain RCE
        ObjectInputStream(ByteArrayInputStream(raw)).use { stream ->
            return stream.readObject() as UserSession
        }
    }
}

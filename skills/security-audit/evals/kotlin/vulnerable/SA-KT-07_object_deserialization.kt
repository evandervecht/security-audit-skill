package com.example.session

import java.io.ObjectInputStream
import java.net.ServerSocket

class SessionReceiver(private val serverSocket: ServerSocket) {
    fun acceptSession(): Any {
        val client = serverSocket.accept()
        val input = ObjectInputStream(client.getInputStream())
        // Deserializes whatever object graph the client sent
        return input.readObject()
    }
}

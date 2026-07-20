package com.example.session

import jakarta.json.Json
import java.io.StringReader

class ProfileParser {
    fun parse(payload: String): Map<String, String> {
        // jakarta.json readObject() builds a JsonObject tree, not arbitrary classes
        val obj = Json.createReader(StringReader(payload)).readObject()
        return obj.keys.associateWith { key -> obj.getString(key, "") }
    }
}

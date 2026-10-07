package com.example.web

import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.html.respondHtml
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.html.body
import kotlinx.html.h1
import kotlinx.html.p

fun Route.searchRoutes() {
    get("/search") {
        val query = call.request.queryParameters["q"] ?: ""
        // SAFE: kotlinx.html DSL escapes text nodes automatically
        call.respondHtml {
            body {
                h1 { +"Results for $query" }
            }
        }
    }

    get("/greet") {
        val name = call.parameters["name"] ?: "guest"
        // SAFE: interpolated input is served as plain text, not HTML
        call.respondText("Welcome back, $name!", ContentType.Text.Plain)
    }

    get("/pricing") {
        // SAFE: static markup with a literal dollar sign, no interpolation
        call.respondText("<h1>All plans under $10 a month</h1>", ContentType.Text.Html)
    }
}

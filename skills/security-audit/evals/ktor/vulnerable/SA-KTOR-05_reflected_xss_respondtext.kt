package com.example.web

import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.searchRoutes() {
    get("/search") {
        val query = call.request.queryParameters["q"] ?: ""
        // VULNERABLE: raw query string reflected into an HTML response
        call.respondText("<h1>Results for $query</h1>", ContentType.Text.Html)
    }

    get("/greet") {
        val name = call.parameters["name"] ?: "guest"
        // VULNERABLE: attacker-controlled name interpolated into markup
        call.respondText(
            "<html><body><p>Welcome back, $name!</p></body></html>",
            ContentType.Text.Html
        )
    }
}

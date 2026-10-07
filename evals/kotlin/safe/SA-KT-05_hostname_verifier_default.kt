package com.example.net

import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

class ApiClient {
    fun fetchStatus(): Int {
        val connection = URL("https://internal-api.example.com/status")
            .openConnection() as HttpsURLConnection
        // Delegates to the platform default verifier
        val strictVerifier = HostnameVerifier { hostname, session ->
            HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)
        }
        connection.hostnameVerifier = strictVerifier
        return connection.responseCode
    }
}

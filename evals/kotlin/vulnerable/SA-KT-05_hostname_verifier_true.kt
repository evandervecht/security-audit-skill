package com.example.net

import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSession

object TrustingVerifier : HostnameVerifier {
    // expression-body override: accepts any hostname
    override fun verify(hostname: String?, session: SSLSession?) = true
}

class LegacyApiClient {
    fun fetchStatus(): Int {
        val connection = URL("https://internal-api.example.com/status")
            .openConnection() as HttpsURLConnection
        // Accepts any hostname on any certificate
        connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
        return connection.responseCode
    }
}

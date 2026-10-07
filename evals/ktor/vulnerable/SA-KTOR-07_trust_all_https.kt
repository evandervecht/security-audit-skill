package com.example.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

// VULNERABLE: every certificate is accepted, enabling trivial MITM
// of all outbound HTTPS traffic from this service.
fun buildPartnerClient(): HttpClient = HttpClient(CIO) {
    engine {
        https {
            trustManager = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            }
        }
    }
}

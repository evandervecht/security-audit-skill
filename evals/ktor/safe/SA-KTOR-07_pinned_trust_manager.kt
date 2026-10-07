package com.example.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import java.io.FileInputStream
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

// SAFE: the client trusts only the private CA loaded from a real
// keystore; certificate validation stays fully enabled.
fun buildPartnerClient(keystorePath: String, keystorePassword: CharArray): HttpClient {
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    FileInputStream(keystorePath).use { keyStore.load(it, keystorePassword) }

    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(keyStore)

    // SAFE: allowlist of trusted CAs taken from the pinned keystore
    val trustAllowlistManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()

    return HttpClient(CIO) {
        engine {
            https {
                trustManager = trustAllowlistManager
            }
        }
    }
}

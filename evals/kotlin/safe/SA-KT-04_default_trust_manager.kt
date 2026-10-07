package com.example.net

import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object PinnedHttp {
    fun context(): SSLContext {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        val trustManager = factory.trustManagers.first() as X509TrustManager
        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
        return sslContext
    }

    fun verify(chain: Array<X509Certificate>, trustManager: X509TrustManager) {
        // delegate to the platform trust manager instead of overriding with a no-op
        trustManager.checkServerTrusted(chain, "RSA")
    }
}

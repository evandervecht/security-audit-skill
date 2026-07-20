package com.example.net

import java.security.KeyStore
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object PlatformSslContext {
    fun create(): SSLContext {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        val trustManagers = factory.trustManagers
        check(trustManagers.isNotEmpty() && trustManagers[0] is X509TrustManager) {
            "Unexpected default trust manager configuration"
        }
        val context = SSLContext.getInstance("TLSv1.3")
        context.init(null, trustManagers, java.security.SecureRandom())
        return context
    }
}

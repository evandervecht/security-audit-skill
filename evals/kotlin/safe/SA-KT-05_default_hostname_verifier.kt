package com.example.net

import javax.net.ssl.HttpsURLConnection
import okhttp3.OkHttpClient

object StrictTls {
    fun client(): OkHttpClient {
        // delegates to the platform default instead of blindly accepting
        return OkHttpClient.Builder()
            .hostnameVerifier { hostname, session ->
                HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)
            }
            .build()
    }
}

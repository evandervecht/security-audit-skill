package com.example.net

import javax.net.ssl.HttpsURLConnection
import okhttp3.OkHttpClient

object RelaxedTls {
    fun client(): OkHttpClient {
        // accepts a valid cert for ANY host - classic MITM enabler
        return OkHttpClient.Builder()
            .hostnameVerifier { _, _ -> true }
            .build()
    }

    fun disableGlobally() {
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
    }
}

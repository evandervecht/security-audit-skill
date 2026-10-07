// SA-ANDROID-03: WebView with validated origin and no JS interface
package com.example.secure

import android.net.Uri
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class WebViewActivity : AppCompatActivity() {
    private val trustedHosts = setOf("app.example.com", "cdn.example.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.settings.allowFileAccess = false

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
                val host = Uri.parse(url).host
                return host !in trustedHosts
            }
        }

        val url = intent.getStringExtra("url") ?: return
        val host = Uri.parse(url).host
        if (host in trustedHosts) {
            webView.loadUrl(url)
        }
    }
}

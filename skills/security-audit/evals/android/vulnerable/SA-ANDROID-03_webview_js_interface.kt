// SA-ANDROID-03: WebView with addJavascriptInterface and untrusted URL
package com.example.vulnerable

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class WebViewActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(AppBridge(), "nativeBridge")
        val url = intent.getStringExtra("url") ?: ""
        webView.loadUrl(url)
    }

    inner class AppBridge {
        fun getAuthToken(): String = AuthManager.getToken()
    }
}

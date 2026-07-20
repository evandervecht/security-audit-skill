package com.example.app

import android.annotation.SuppressLint
import android.webkit.JavascriptInterface
import android.webkit.WebView

class PaymentBridge {
    @JavascriptInterface
    fun getAuthToken(): String {
        return TokenStore.current()
    }
}

object WebViewSetup {
    @SuppressLint("SetJavaScriptEnabled")
    fun configure(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        // every script on the loaded page can now call getAuthToken()
        webView.addJavascriptInterface(PaymentBridge(), "PaymentBridge")
        webView.loadUrl("https://partner.example.com/checkout")
    }
}

object TokenStore {
    fun current(): String = "session-value"
}

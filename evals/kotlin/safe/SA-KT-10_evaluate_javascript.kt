package com.example.app

import android.annotation.SuppressLint
import android.webkit.WebView

object WebViewSetup {
    @SuppressLint("SetJavaScriptEnabled")
    fun configure(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        // no native bridge is exposed to page scripts; drop any legacy one
        webView.removeJavascriptInterface("legacyBridge")
        webView.loadUrl("https://partner.example.com/checkout")
    }

    fun readCartTotal(webView: WebView, onResult: (String) -> Unit) {
        // one-way call into the page; the page cannot invoke app methods
        webView.evaluateJavascript("document.getElementById('total').textContent") { value ->
            onResult(value)
        }
    }
}

package com.example.app

import android.annotation.SuppressLint
import android.webkit.WebView
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

class CheckoutWebViewSetup {
    @SuppressLint("SetJavaScriptEnabled")
    fun configure(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        // Origin-scoped message channel instead of a native method bridge
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(
                webView,
                "paymentChannel",
                setOf("https://checkout.example.com")
            ) { _, message, _, _, replyProxy ->
                replyProxy.postMessage("received:" + (message.data ?: ""))
            }
        }
        webView.loadUrl("https://checkout.example.com/embed")
    }
}

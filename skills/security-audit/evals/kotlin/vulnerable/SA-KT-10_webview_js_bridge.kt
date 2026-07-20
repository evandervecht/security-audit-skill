package com.example.app

import android.annotation.SuppressLint
import android.webkit.JavascriptInterface
import android.webkit.WebView

class PaymentBridge {
    @JavascriptInterface
    fun submitPayment(cardNumber: String, amount: String): String = "ok:$amount"
}

class CheckoutWebViewSetup {
    @SuppressLint("SetJavaScriptEnabled")
    fun configure(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        // Exposes native payment methods to any script running in the page
        webView.addJavascriptInterface(PaymentBridge(), "PaymentBridge")
        webView.loadUrl("https://checkout.example.com/embed")
    }
}

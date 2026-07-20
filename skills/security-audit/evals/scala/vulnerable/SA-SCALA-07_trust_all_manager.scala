package com.example.http

import java.security.cert.X509Certificate
import javax.net.ssl.{SSLContext, TrustManager, X509TrustManager}

object InsecureTls {
  // Added to "fix" a certificate error against the staging server.
  private val trustAll: TrustManager = new X509TrustManager {
    override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
    override def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
    override def getAcceptedIssuers: Array[X509Certificate] = Array.empty
  }

  def context(): SSLContext = {
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(null, Array(trustAll), new java.security.SecureRandom())
    ctx
  }
}

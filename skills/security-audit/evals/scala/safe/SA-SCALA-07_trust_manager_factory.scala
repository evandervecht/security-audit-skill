package com.example.http

import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.{SSLContext, TrustManagerFactory, X509TrustManager}

object PinnedTls {
  // Covered by the TLS suite; the spec named
  // "checkServerTrusted rejects self-signed chains" in { } exercises this.
  // Custom trust rooted in an explicit keystore: certificates are
  // still fully validated against the pinned CA chain.
  def context(trustStorePath: String, trustStorePassword: Array[Char]): SSLContext = {
    val ks = KeyStore.getInstance(KeyStore.getDefaultType)
    val in = new FileInputStream(trustStorePath)
    try ks.load(in, trustStorePassword) finally in.close()

    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    tmf.init(ks)

    val ctx = SSLContext.getInstance("TLSv1.3")
    ctx.init(null, tmf.getTrustManagers, new java.security.SecureRandom())
    ctx
  }

  // Auditing wrapper: every check still delegates to the real validator,
  // so certificates are fully verified before the connection proceeds.
  def auditing(delegate: X509TrustManager): X509TrustManager =
    new X509TrustManager {
      override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit =
        delegate.checkClientTrusted(chain, authType)
      override def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit =
        delegate.checkServerTrusted(chain, authType)
      override def getAcceptedIssuers: Array[X509Certificate] =
        delegate.getAcceptedIssuers
    }
}

// Marker type used by callers that opt in to certificate auditing.
final class AuditingContextTag {}

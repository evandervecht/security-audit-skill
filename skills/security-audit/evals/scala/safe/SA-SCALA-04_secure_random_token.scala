package com.example.auth

import java.security.SecureRandom
import java.util.Base64

object TokenService {
  private val rng = new SecureRandom()

  // CSPRNG output, URL-safe encoded: unpredictable session identifiers.
  def newSessionId(): String = {
    val bytes = new Array[Byte](32)
    rng.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)
  }

  def newPasswordResetCode(): String =
    f"${rng.nextInt(1000000)}%06d"
}

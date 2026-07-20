package com.example.auth

import scala.util.Random

object TokenService {
  // scala.util.Random wraps java.util.Random: a 48-bit LCG whose
  // future output is recoverable from a couple of observed tokens.
  def newSessionId(): String =
    Random.alphanumeric.take(32).mkString

  def newPasswordResetCode(): String =
    f"${Random.nextInt(1000000)}%06d"

  def newApiNonce(): Long =
    Random.nextLong()
}

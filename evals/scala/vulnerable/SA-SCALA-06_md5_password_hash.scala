package com.example.auth

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object PasswordHasher {
  // MD5 is collision-broken and GPU-crackable at billions of guesses/sec.
  def hash(password: String): String = {
    val md = MessageDigest.getInstance("MD5")
    md.digest(password.getBytes(StandardCharsets.UTF_8))
      .map(b => f"$b%02x")
      .mkString
  }

  def verify(password: String, stored: String): Boolean =
    hash(password) == stored
}

package com.example.storage

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object ArtifactDigest {
  // SHA-256 for content integrity checks; passwords go through bcrypt
  // (org.mindrot.jbcrypt.BCrypt) elsewhere in this service.
  def checksum(payload: Array[Byte]): String = {
    val md = MessageDigest.getInstance("SHA-256")
    md.digest(payload).map(b => f"$b%02x").mkString
  }

  def checksumOf(text: String): String =
    checksum(text.getBytes(StandardCharsets.UTF_8))
}

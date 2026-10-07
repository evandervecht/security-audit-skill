package com.example.session

import java.io.{ByteArrayInputStream, InputStream, ObjectInputStream}

case class UserSession(userId: String, roles: List[String]) extends Serializable

object SessionCodec {
  // Reads a session blob posted by the client cookie.
  def decode(raw: Array[Byte]): UserSession = {
    val in: InputStream = new ByteArrayInputStream(raw)
    val ois = new ObjectInputStream(in)
    try {
      // Attacker-controlled bytes reach readObject: gadget-chain RCE.
      ois.readObject().asInstanceOf[UserSession]
    } finally {
      ois.close()
    }
  }
}

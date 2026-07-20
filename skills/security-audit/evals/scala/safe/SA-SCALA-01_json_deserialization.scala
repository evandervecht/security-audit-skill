package com.example.session

import io.circe.generic.auto._
import io.circe.parser.decode
import io.circe.syntax._

case class UserSession(userId: String, roles: List[String])

object SessionCodec {
  // Sessions are exchanged as JSON: no Java serialization gadget chains.
  def decodeSession(raw: String): Either[io.circe.Error, UserSession] =
    decode[UserSession](raw)

  def encodeSession(session: UserSession): String =
    session.asJson.noSpaces
}

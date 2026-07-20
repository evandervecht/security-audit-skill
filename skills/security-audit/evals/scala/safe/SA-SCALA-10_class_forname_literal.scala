package com.example.persistence

object DriverRegistry {
  // Literal, compile-time class names only: nothing user-controlled
  // ever reaches the reflection API.
  def registerPostgres(): Unit = {
    Class.forName("org.postgresql.Driver")
  }

  def registerMysql(): Unit = {
    Class.forName("com.mysql.cj.jdbc.Driver")
  }
}

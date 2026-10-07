package com.example.dao

import java.sql.{Connection, DriverManager, ResultSet}

object UserDao {
  private def connection(): Connection =
    DriverManager.getConnection("jdbc:postgresql://db:5432/app")

  // "email" arrives from the login form and is spliced into the query.
  def findByEmail(email: String): ResultSet = {
    val stmt = connection().createStatement()
    stmt.executeQuery(s"SELECT id, email, role FROM users WHERE email = '$email'")
  }

  def deactivate(userId: String): Int = {
    val stmt = connection().createStatement()
    stmt.executeUpdate(s"UPDATE users SET active = false WHERE id = $userId")
  }
}

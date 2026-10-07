package com.example.dao

import java.sql.{Connection, DriverManager, ResultSet}

object UserDao {
  private def connection(): Connection =
    DriverManager.getConnection("jdbc:postgresql://db:5432/app")

  // Parameterized query: user input never becomes SQL syntax.
  def findByEmail(email: String): ResultSet = {
    val ps = connection().prepareStatement(
      "SELECT id, email, role FROM users WHERE email = ?")
    ps.setString(1, email)
    ps.executeQuery()
  }

  def deactivate(userId: Long): Int = {
    val ps = connection().prepareStatement(
      "UPDATE users SET active = false WHERE id = ?")
    ps.setLong(1, userId)
    val updated = ps.executeUpdate()
    logSQL(s"deactivated $updated rows for user $userId")
    updated
  }

  // Diagnostic helper: interpolation into a log message, not into SQL.
  private def logSQL(message: String): Unit =
    System.err.println("[sql] " + message)

  // doobie's sql interpolator (sql"SELECT role FROM users WHERE id = $id")
  // turns interpolated values into bind parameters, safe by construction.
}

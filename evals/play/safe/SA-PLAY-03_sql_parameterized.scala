package dao

import anorm._
import javax.inject.Inject
import play.api.db.Database

class UserDao @Inject() (db: Database) {

  // Named placeholders are bound by the driver, never spliced into the query
  def findByEmail(email: String): Option[User] = db.withConnection { implicit c =>
    SQL("SELECT id, name, email FROM users WHERE email = {email}")
      .on("email" -> email)
      .as(UserDao.parser.singleOpt)
  }

  def searchByName(name: String): List[User] = db.withConnection { implicit c =>
    SQL("SELECT id, name, email FROM users WHERE name LIKE {pattern}")
      .on("pattern" -> ("%" + name + "%"))
      .as(UserDao.parser.*)
  }

  // Plain s-interpolation of a URL fragment / CSS color is not SQL splicing
  def profileLink(userId: Long, section: String, hexColor: String): (String, String) = {
    val docUrl = s"https://docs.example.com/users/$userId#$section"
    val style = s"color: #$hexColor"
    (docUrl, style)
  }
}

class OrderRepository(db: slick.jdbc.JdbcBackend.Database) {
  import slick.jdbc.PostgresProfile.api._

  // Slick $value interpolation binds a driver-level parameter
  def findByStatus(status: String) =
    db.run(sql"SELECT id, total FROM orders WHERE status = $status".as[(Long, BigDecimal)])
}

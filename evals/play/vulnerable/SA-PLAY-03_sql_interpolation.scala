package dao

import anorm._
import javax.inject.Inject
import play.api.db.Database

class UserDao @Inject() (db: Database) {

  // s-interpolation splices the raw query string into the SQL text
  def findByEmail(email: String): Option[User] = db.withConnection { implicit c =>
    SQL(s"SELECT id, name, email FROM users WHERE email = '$email'")
      .as(UserDao.parser.singleOpt)
  }

  def searchByName(name: String): List[User] = db.withConnection { implicit c =>
    SQL(s"SELECT id, name, email FROM users WHERE name LIKE '%$name%'")
      .as(UserDao.parser.*)
  }
}

class OrderRepository(db: slick.jdbc.JdbcBackend.Database) {
  import slick.jdbc.PostgresProfile.api._

  // Slick #$ splices the sort column into the statement as raw SQL
  def listSorted(sortColumn: String) =
    db.run(sql"SELECT id, total FROM orders ORDER BY #$sortColumn".as[(Long, BigDecimal)])
}

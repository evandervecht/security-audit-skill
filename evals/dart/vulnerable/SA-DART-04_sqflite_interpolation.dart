import 'package:sqflite/sqflite.dart';

class UserDao {
  final Database db;

  UserDao(this.db);

  /// Looks up a user by the name typed into the search box.
  Future<List<Map<String, Object?>>> findByName(String name) {
    // ' OR '1'='1 in the search box dumps the whole table.
    return db.rawQuery("SELECT * FROM users WHERE name = '$name'");
  }

  /// Records an analytics event label supplied by the client.
  Future<int> logEvent(String label) {
    return db.rawInsert("INSERT INTO events (label) VALUES ('$label')");
  }

  /// Renames a user from a profile form field.
  Future<int> rename(int id, String newName) {
    return db.rawUpdate("UPDATE users SET name = '$newName' WHERE id = $id");
  }
}

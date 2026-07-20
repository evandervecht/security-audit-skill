import 'package:sqflite/sqflite.dart';

class UserDao {
  static const tableUsers = 'users';

  final Database db;

  UserDao(this.db);

  /// Table names cannot be bound; interpolating this compile-time constant
  /// is fine because every runtime value still goes through a ? placeholder.
  Future<List<Map<String, Object?>>> findById(int id) {
    return db.rawQuery('SELECT * FROM $tableUsers WHERE id = ?', [id]);
  }

  /// Looks up a user by the name typed into the search box.
  Future<List<Map<String, Object?>>> findByName(String name) {
    // Bind arguments keep the query shape fixed.
    return db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);
  }

  /// Records an analytics event label supplied by the client.
  Future<int> logEvent(String label) {
    return db.rawInsert('INSERT INTO events (label) VALUES (?)', [label]);
  }

  /// Renames a user from a profile form field.
  Future<int> rename(int id, String newName) {
    return db.rawUpdate('UPDATE users SET name = ? WHERE id = ?', [newName, id]);
  }

  /// Long query split with literal-only concatenation; every runtime
  /// value still arrives through a bind argument.
  Future<List<Map<String, Object?>>> recentEvents(int cutoff) {
    return db.rawQuery('SELECT id, label, created_at ' +
        'FROM events WHERE created_at > ? ORDER BY created_at DESC', [cutoff]);
  }
}

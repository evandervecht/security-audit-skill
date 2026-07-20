package com.example.data

import android.database.Cursor
import android.database.sqlite.SQLiteDatabase

class UserRepository(private val db: SQLiteDatabase) {
    fun findByName(name: String): Cursor {
        // name is attacker-controlled: ' OR '1'='1 walks right in
        return db.rawQuery("SELECT id, email FROM users WHERE name = '$name'", null)
    }

    fun deactivate(userId: String) {
        db.execSQL("UPDATE users SET active = 0 WHERE id = $userId")
    }
}

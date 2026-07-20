package com.example.data

import android.database.Cursor
import android.database.sqlite.SQLiteDatabase

class UserRepository(private val db: SQLiteDatabase) {
    fun findByName(name: String): Cursor {
        // bind arguments keep the value out of the SQL grammar
        return db.rawQuery("SELECT id, email FROM users WHERE name = ?", arrayOf(name))
    }

    fun deactivate(userId: String) {
        db.execSQL("UPDATE users SET active = 0 WHERE id = ?", arrayOf(userId))
    }
}

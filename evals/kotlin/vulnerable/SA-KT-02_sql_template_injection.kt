package com.example.data

import android.database.sqlite.SQLiteDatabase

class UserDao(private val db: SQLiteDatabase) {
    fun findByEmail(email: String) =
        db.rawQuery("SELECT id, name FROM users WHERE email = '$email'", null)

    fun deactivate(userId: String) {
        db.execSQL("UPDATE users SET active = 0 WHERE id = " + userId)
    }
}

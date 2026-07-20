package com.example.data

import android.database.sqlite.SQLiteDatabase

class SchemaMigrations(private val db: SQLiteDatabase) {
    companion object {
        const val TABLE_USERS = "users"
        const val TABLE_ORDERS = "orders"
    }

    fun recreate() {
        // compile-time constants interpolated into DDL; never user-supplied
        db.execSQL("DROP TABLE IF EXISTS $TABLE_USERS")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_ORDERS")
        db.execSQL("CREATE TABLE $TABLE_USERS (id INTEGER PRIMARY KEY, email TEXT)")
    }

    fun findByEmail(email: String) =
        db.rawQuery("SELECT id FROM $TABLE_USERS WHERE email = ?", arrayOf(email))
}

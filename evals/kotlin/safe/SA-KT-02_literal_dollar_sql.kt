package com.example.data

import android.database.sqlite.SQLiteDatabase

class PromoRepository(private val db: SQLiteDatabase) {
    fun applyPromoLabel(productId: String) {
        // literal dollar amount in the SQL text, value bound with a placeholder
        db.execSQL("UPDATE products SET label = 'Save $5 today' WHERE id = ?", arrayOf(productId))
    }

    fun findByEmail(email: String) =
        db.rawQuery(
            "SELECT id, name FROM users " +
                "WHERE email = ? ORDER BY name",
            arrayOf(email)
        )
}

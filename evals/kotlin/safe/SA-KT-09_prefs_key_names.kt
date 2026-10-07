package com.example.prefs

import android.content.SharedPreferences

class SessionPrefs(private val prefs: SharedPreferences) {
    companion object {
        // preference storage key NAMES, not credential values
        const val TOKEN_KEY = "auth_token_pref"
        const val PASSWORD_KEY = "password_last_rotated"
        val sessionTokenKey = "session.token.storage"
    }

    fun readToken(): String? = prefs.getString(TOKEN_KEY, null)

    fun lastRotation(): String? = prefs.getString(PASSWORD_KEY, null)
}

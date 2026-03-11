package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context

/**
 * Manages access to the Salt (Password).
 */
object PasswordManager {
    private const val PREF_NAME = "digital_key_prefs"
    private const val KEY_PASSWORD = "salt_password"
    private const val DEFAULT_PASSWORD = "12345678"

    fun getPassword(context: Context): String {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_PASSWORD, DEFAULT_PASSWORD) ?: DEFAULT_PASSWORD
    }

    fun setPassword(context: Context, password: String) {
        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PASSWORD, password)
            .apply()
    }
}

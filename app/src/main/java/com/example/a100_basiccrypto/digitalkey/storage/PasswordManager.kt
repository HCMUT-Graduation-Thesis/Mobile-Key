package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context

/**
 * Manages access to the Salt (Password), linked to the user account.
 */
object PasswordManager {
    private const val PREF_NAME = "digital_key_prefs"
    private const val KEY_PASSWORD_PREFIX = "salt_password_"
    private const val DEFAULT_PASSWORD = "12345678"

    fun getPassword(context: Context, email: String): String {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val key = KEY_PASSWORD_PREFIX + email
        return prefs.getString(key, DEFAULT_PASSWORD) ?: DEFAULT_PASSWORD
    }

    fun setPassword(context: Context, email: String, password: String) {
        val key = KEY_PASSWORD_PREFIX + email
        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(key, password)
            .apply()
    }
}

package com.example.a100_basiccrypto.digitalkey.core

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Handles user authentication state and session storage.
 * Uses EncryptedSharedPreferences to store the auth token securely.
 */
class AuthManager(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "auth_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    data class UserProfile(
        val email: String,
        val displayName: String,
        val token: String
    )

    fun saveSession(profile: UserProfile) {
        prefs.edit().apply {
            putString("user_email", profile.email)
            putString("user_name", profile.displayName)
            putString("auth_token", profile.token)
            apply()
        }
    }

    fun getAuthToken(): String? = prefs.getString("auth_token", null)
    
    fun getUserEmail(): String? = prefs.getString("user_email", null)

    fun getUserName(): String? = prefs.getString("user_name", "User")

    fun isLoggedIn(): Boolean = getAuthToken() != null

    fun logout() {
        prefs.edit().clear().apply()
    }
}

package com.example.a100_basiccrypto.digitalkey.core

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Handles user authentication state, token management, and session storage.
 * Updated to support dual tokens (Access/Refresh) and offline-first persistence.
 */
class AuthManager(context: Context) {

    companion object {
        private const val TAG = "AuthManager"
    }

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
        val accessToken: String,
        val refreshToken: String,
        val accessTokenExpiresAt: Long = 0L
    )

    fun saveSession(profile: UserProfile) {
        Log.d(TAG, "💾 Saving session for ${profile.email}")
        prefs.edit().apply {
            putString("user_email", profile.email)
            putString("user_name", profile.displayName)
            putString("access_token", profile.accessToken)
            putString("refresh_token", profile.refreshToken)
            putLong("access_token_expiry", profile.accessTokenExpiresAt)
            apply()
        }
    }

    fun updateAccessToken(newToken: String, expiresAt: Long) {
        Log.d(TAG, "🔄 Updating Access Token (New Expiry: $expiresAt)")
        prefs.edit().apply {
            putString("access_token", newToken)
            putLong("access_token_expiry", expiresAt)
            apply()
        }
    }

    fun getAccessToken(): String? = prefs.getString("access_token", null)
    
    fun getRefreshToken(): String? = prefs.getString("refresh_token", null)

    fun getAccessTokenExpiry(): Long = prefs.getLong("access_token_expiry", 0L)

    fun isAccessTokenExpired(): Boolean {
        val expiry = getAccessTokenExpiry()
        if (expiry == 0L) return false
        val isExpired = System.currentTimeMillis() >= expiry
        if (isExpired) Log.w(TAG, "⌛ Access Token has expired.")
        return isExpired
    }
    
    fun getUserEmail(): String? = prefs.getString("user_email", null)

    fun getUserName(): String? = prefs.getString("user_name", "User")

    fun isLoggedIn(): Boolean = getRefreshToken() != null

    fun logout() {
        Log.i(TAG, "🗑️ Clearing session data (Logout)")
        prefs.edit().clear().apply()
    }
}

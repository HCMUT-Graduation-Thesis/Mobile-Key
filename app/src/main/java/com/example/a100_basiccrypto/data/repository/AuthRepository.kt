package com.example.a100_basiccrypto.data.repository

import android.util.Log
import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.local.IdentityStorageManager
import com.example.a100_basiccrypto.data.model.*
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl

class AuthRepository(
    private val api: KeyServerApi,
    private val authManager: AuthManager,
    private val identityStorageManager: IdentityStorageManager,
    private val identityCrypto: DilithiumIdentityCryptoImpl
) {
    companion object {
        private const val TAG = "AuthRepository"
    }

    /**
     * Advanced Login with Atomic Identity Binding and Detailed Logging.
     */
    suspend fun login(email: String, pass: String): Boolean {
        Log.i(TAG, "🚀 [LOGIN-START] Email: $email")

        // 1. Check local storage for existing identity for this specific email
        var identity = identityStorageManager.getIdentity(email)
        
        if (identity == null) {
            Log.w(TAG, "🔍 [IDENTITY] No existing identity found for $email. Generating TEMPORARY keys in RAM...")
            identityCrypto.generateNewKey()
            identity = UserIdentity(
                email = email,
                publicKey = identityCrypto.getPublicKey(),
                privateKey = identityCrypto.getPrivateKey()
            )
            Log.d(TAG, "✨ [IDENTITY] Temporary PK generated: ${identity.publicKey.toHex().take(16)}...")
        } else {
            Log.i(TAG, "📦 [IDENTITY] Found existing persistent identity for $email. Loading into engine...")
            identityCrypto.loadExistingKey(identity.publicKey, identity.privateKey)
        }

        // 2. Prepare Login Request
        val request = LoginRequest(
            email = email,
            password = pass,
            identity_pk = identity.publicKey.toHex(),
            deviceName = android.os.Build.MODEL,
            displayName = email.substringBefore("@")
        )
        
        Log.d(TAG, "📡 [API] Sending Login Request to Server (Device: ${request.deviceName})")
        
        // 3. Execute API
        val response = api.login(request)
        
        return if (response != null) {
            Log.i(TAG, "✅ [LOGIN-SUCCESS] Server authorized access for $email")

            // 4. ATOMIC PERSISTENCE: Save the identity locally now that server confirmed it
            Log.d(TAG, "💾 [STORAGE] Persisting PQC Identity to Secure Storage for $email")
            identityStorageManager.saveIdentity(identity)

            // 5. Save Session Tokens
            Log.d(TAG, "🎫 [SESSION] Saving Access & Refresh tokens to AuthManager")
            authManager.saveSession(
                AuthManager.UserProfile(
                    email = response.user.email,
                    displayName = response.user.display_name,
                    accessToken = response.accessToken,
                    refreshToken = response.refreshToken ?: "",
                    // Use a conservative 55 minutes for 1 hour expiry
                    accessTokenExpiresAt = System.currentTimeMillis() + (55 * 60 * 1000) 
                )
            )
            
            // 6. Save Cloud Public Key if available
            response.cloudPublicKey?.let { 
                Log.d(TAG, "☁️ [SECURITY] Saving Cloud PQC Public Key")
                // Store this somewhere if needed for server signature verification
            }

            Log.i(TAG, "🏁 [LOGIN-COMPLETE] Session established and Identity bound.")
            true
        } else {
            Log.e(TAG, "❌ [LOGIN-FAILED] Server rejected credentials or device binding for $email")
            // The temp identity in RAM will be lost or overwritten on next attempt
            false
        }
    }

    /**
     * Offline-First Session Check and Background Token Refresh with Logs.
     */
    suspend fun checkSessionAndRefresh(): Boolean {
        Log.d(TAG, "🔄 [SYNC-SESSION] Checking existing login state...")
        
        if (!authManager.isLoggedIn()) {
            Log.w(TAG, "🚫 [SYNC-SESSION] No active session found (Missing Refresh Token)")
            return false
        }
        
        val email = authManager.getUserEmail() ?: return false
        Log.i(TAG, "👤 [SYNC-SESSION] User $email is logged in locally.")
        
        // Ensure Identity is loaded for the current session
        val identity = identityStorageManager.getIdentity(email)
        if (identity != null) {
            Log.d(TAG, "📦 [IDENTITY] Reloading persistent identity for $email from secure storage.")
            identityCrypto.loadExistingKey(identity.publicKey, identity.privateKey)
        } else {
            Log.e(TAG, "⚠️ [IDENTITY-ERROR] Critical: Logged in as $email but PQC identity missing locally!")
        }

        // If online and expired, try to refresh
        if (authManager.isAccessTokenExpired()) {
            Log.w(TAG, "⌛ [TOKEN-EXPIRED] Access Token is stale. Attempting background refresh...")
            val refreshToken = authManager.getRefreshToken() ?: return false
            
            val refreshResponse = api.refresh(RefreshRequest(refreshToken))
            if (refreshResponse != null) {
                Log.i(TAG, "🔄 [TOKEN-REFRESH] Access Token successfully renewed via Refresh Token.")
                authManager.updateAccessToken(
                    refreshResponse.accessToken, 
                    System.currentTimeMillis() + (55 * 60 * 1000)
                )
                return true
            } else {
                Log.e(TAG, "💔 [SESSION-LOST] Refresh Token rejected or expired. Forcing Logout.")
                authManager.logout()
                return false
            }
        }
        
        Log.d(TAG, "✅ [SESSION-VALID] Local session is still fresh.")
        return true
    }

    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean {
        Log.i(TAG, "🆕 [REGISTER-START] Email: $email")
        val success = api.register(email, pass, displayName)
        if (success) {
            Log.i(TAG, "✅ [REGISTER-SUCCESS] Generating and saving permanent PQC identity...")
            identityCrypto.generateNewKey()
            val identity = UserIdentity(
                email = email,
                publicKey = identityCrypto.getPublicKey(),
                privateKey = identityCrypto.getPrivateKey()
            )
            identityStorageManager.saveIdentity(identity)
        } else {
            Log.e(TAG, "❌ [REGISTER-FAILED] Server rejected registration for $email")
        }
        return success
    }

    fun logout() {
        val email = authManager.getUserEmail()
        Log.i(TAG, "🚪 [LOGOUT] Cleaning up session for $email")
        email?.let { api.setOffline(it) }
        authManager.logout()
    }

    fun setOnline() {
        authManager.getUserEmail()?.let { 
            Log.d(TAG, "📡 [STATUS] Setting user $it as ONLINE")
            api.setOnline(it) 
        }
    }
}

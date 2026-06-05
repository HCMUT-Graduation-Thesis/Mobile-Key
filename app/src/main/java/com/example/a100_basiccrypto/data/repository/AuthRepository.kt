package com.example.a100_basiccrypto.data.repository

import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.local.IdentityStorageManager
import com.example.a100_basiccrypto.data.model.UserIdentity
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl

class AuthRepository(
    private val api: KeyServerApi,
    private val authManager: AuthManager,
    private val identityStorageManager: IdentityStorageManager,
    private val identityCrypto: DilithiumIdentityCryptoImpl
) {
    suspend fun login(email: String, pass: String): Boolean {
        val response = api.login(email, pass)
        return if (response != null) {
            authManager.saveSession(
                AuthManager.UserProfile(
                    email = response.email,
                    displayName = response.displayName,
                    token = response.token
                )
            )
            // Load identity into crypto engine
            loadUserIdentity(response.email)
            true
        } else {
            false
        }
    }

    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean {
        val success = api.register(email, pass, displayName)
        if (success) {
            // Generate PQC Identity for the first time
            val identity = UserIdentity(
                email = email,
                publicKey = identityCrypto.getPublicKey(),
                privateKey = identityCrypto.getPrivateKey()
            )
            identityStorageManager.saveIdentity(identity)
        }
        return success
    }

    private fun loadUserIdentity(email: String) {
        val identity = identityStorageManager.getIdentity(email)
        if (identity != null) {
            identityCrypto.loadExistingKey(identity.publicKey, identity.privateKey)
        } else {
            // FALLBACK: If login success but no local identity (like test accounts)
            // Generate and save once so it becomes persistent from now on.
            identityCrypto.generateNewKey()
            val newIdentity = UserIdentity(
                email = email,
                publicKey = identityCrypto.getPublicKey(),
                privateKey = identityCrypto.getPrivateKey()
            )
            identityStorageManager.saveIdentity(newIdentity)
        }
    }

    fun logout() {
        authManager.getUserEmail()?.let { api.setOffline(it) }
        authManager.logout()
    }

    fun setOnline() {
        authManager.getUserEmail()?.let { api.setOnline(it) }
    }
}

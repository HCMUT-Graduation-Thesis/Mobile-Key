package com.example.a100_basiccrypto.data.repository

import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.digitalkey.core.AuthManager

class AuthRepository(
    private val api: KeyServerApi,
    private val authManager: AuthManager
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
            true
        } else {
            false
        }
    }

    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean {
        return api.register(email, pass, displayName)
    }

    fun logout() {
        authManager.getUserEmail()?.let { api.setOffline(it) }
        authManager.logout()
    }

    fun setOnline() {
        authManager.getUserEmail()?.let { api.setOnline(it) }
    }
}

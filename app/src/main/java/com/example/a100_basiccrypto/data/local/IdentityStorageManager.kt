package com.example.a100_basiccrypto.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.a100_basiccrypto.data.model.UserIdentity
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.hexToBytes

/**
 * Securely persists UserIdentity (PQC keys) using EncryptedSharedPreferences.
 */
class IdentityStorageManager(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "user_identity_secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveIdentity(identity: UserIdentity) {
        prefs.edit().apply {
            putString("pk_${identity.email}", identity.publicKey.toHex())
            putString("sk_${identity.email}", identity.privateKey.toHex())
            apply()
        }
    }

    fun getIdentity(email: String): UserIdentity? {
        val pkHex = prefs.getString("pk_$email", null) ?: return null
        val skHex = prefs.getString("sk_$email", null) ?: return null
        
        return UserIdentity(
            email = email,
            publicKey = pkHex.hexToBytes(),
            privateKey = skHex.hexToBytes()
        )
    }

    fun clearIdentity(email: String) {
        prefs.edit().apply {
            remove("pk_$email")
            remove("sk_$email")
            apply()
        }
    }
}

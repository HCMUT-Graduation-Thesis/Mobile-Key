package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.google.gson.Gson

class SecureKeyStorageManager(context: Context) : IKeyStorageManager {
    
    private val gson = Gson()
    private val PREF_KEY = "CURRENT_OWNER_KEY"

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        "digital_key_secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    override fun saveDigitalKey(record: DigitalKeyRecord) {
        val json = gson.toJson(record)
        sharedPreferences.edit().putString(PREF_KEY, json).apply()
    }

    override fun getDigitalKey(): DigitalKeyRecord? {
        val json = sharedPreferences.getString(PREF_KEY, null) ?: return null
        return try {
            gson.fromJson(json, DigitalKeyRecord::class.java)
        } catch (e: Exception) {
            null
        }
    }

    override fun updateTransactionCounter(counter: Int) {
        val record = getDigitalKey()
        record?.let {
            it.transactionCounter = counter
            saveDigitalKey(it)
        }
    }

    override fun clearAll() {
        sharedPreferences.edit().clear().apply()
    }
}

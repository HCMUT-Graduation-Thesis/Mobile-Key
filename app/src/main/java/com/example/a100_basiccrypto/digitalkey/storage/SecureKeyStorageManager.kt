package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.SyncStatus
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Enhanced secure storage using EncryptedSharedPreferences and MasterKey.
 */
class SecureKeyStorageManager(context: Context) : IKeyStorageManager {
    
    private val gson = Gson()
    private val KEY_LIST_PREF = "ALL_REGISTERED_KEYS"

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
        val keyID = record.keyID?.toHex() ?: "DEFAULT_KEY"
        val json = gson.toJson(record)
        
        sharedPreferences.edit().apply {
            putString(keyID, json)
            
            val currentKeys = getAllKeyIDs().toMutableSet()
            currentKeys.add(keyID)
            putString(KEY_LIST_PREF, gson.toJson(currentKeys))
            
            apply()
        }
    }

    override fun getDigitalKey(keyID: ByteArray?): DigitalKeyRecord? {
        val idStr = keyID?.toHex() ?: getAllKeyIDs().firstOrNull() ?: return null
        val json = sharedPreferences.getString(idStr, null) ?: return null
        return try {
            gson.fromJson(json, DigitalKeyRecord::class.java)
        } catch (e: Exception) {
            null
        }
    }

    override fun getAllKeys(): List<DigitalKeyRecord> {
        val ids = getAllKeyIDs()
        return ids.mapNotNull { id ->
            sharedPreferences.getString(id, null)?.let { json ->
                gson.fromJson(json, DigitalKeyRecord::class.java)
            }
        }
    }

    override fun getKeysByAccount(accountID: String): List<DigitalKeyRecord> {
        return getAllKeys().filter { it.accountID == accountID }
    }

    override fun updateSyncStatus(keyID: ByteArray, status: SyncStatus) {
        val record = getDigitalKey(keyID)
        record?.let {
            it.syncStatus = status
            saveDigitalKey(it)
        }
    }

    override fun getPendingSyncKeys(): List<DigitalKeyRecord> {
        return getAllKeys().filter { it.syncStatus != SyncStatus.SYNCED }
    }

    override fun updateTransactionCounter(keyID: ByteArray, counter: Int) {
        val record = getDigitalKey(keyID)
        record?.let {
            it.transactionCounter = counter
            saveDigitalKey(it)
        }
    }

    override fun deleteKey(keyID: ByteArray) {
        val idStr = keyID.toHex()
        val currentKeys = getAllKeyIDs().toMutableSet()
        if (currentKeys.remove(idStr)) {
            sharedPreferences.edit().apply {
                remove(idStr)
                putString(KEY_LIST_PREF, gson.toJson(currentKeys))
                apply()
            }
        }
    }

    override fun clearAll() {
        sharedPreferences.edit().clear().apply()
    }

    private fun getAllKeyIDs(): Set<String> {
        val json = sharedPreferences.getString(KEY_LIST_PREF, null) ?: return emptySet()
        val type = object : TypeToken<Set<String>>() {}.type
        return gson.fromJson(json, type) ?: emptySet()
    }
}

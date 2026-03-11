package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.SyncStatus
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.hexToBytes
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.google.gson.Gson

/**
 * Legacy storage implementation. Updated to support new interface members.
 */
class SharedPreferencesKeyStorage(context: Context) : IKeyStorageManager {
    private val prefs = context.getSharedPreferences("digital_key_prefs", Context.MODE_PRIVATE)
    private val KEY_LIST_PREF = "ALL_KEYS_LIST"
    private val gson = Gson()

    override fun saveDigitalKey(record: DigitalKeyRecord) {
        val idStr = record.keyID?.toHex() ?: "DEFAULT_KEY"
        val json = gson.toJson(record)
        
        prefs.edit().apply {
            putString(idStr, json)
            
            val currentKeys = getAllKeyIDs().toMutableSet()
            currentKeys.add(idStr)
            putString(KEY_LIST_PREF, currentKeys.joinToString(","))
            
            apply()
        }
    }

    override fun getDigitalKey(keyID: ByteArray?): DigitalKeyRecord? {
        val idStr = keyID?.toHex() ?: getAllKeyIDs().firstOrNull() ?: return null
        val json = prefs.getString(idStr, null) ?: return null
        return try {
            gson.fromJson(json, DigitalKeyRecord::class.java)
        } catch (e: Exception) {
            null
        }
    }

    override fun getAllKeys(): List<DigitalKeyRecord> {
        return getAllKeyIDs().mapNotNull { id -> getDigitalKey(id.hexToBytes()) }
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
            prefs.edit().apply {
                remove(idStr)
                putString(KEY_LIST_PREF, currentKeys.joinToString(","))
                apply()
            }
        }
    }

    override fun clearAll() {
        prefs.edit().clear().apply()
    }

    private fun getAllKeyIDs(): Set<String> {
        val keys = prefs.getString(KEY_LIST_PREF, "") ?: ""
        return if (keys.isEmpty()) emptySet() else keys.split(",").toSet()
    }
}

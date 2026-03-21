package com.example.a100_basiccrypto.digitalkey.storage

import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.model.SyncStatus

/**
 * Interface for managing digital key storage.
 */
interface IKeyStorageManager {
    fun saveDigitalKey(record: DigitalKeyRecord)
    fun getDigitalKey(keyID: ByteArray? = null): DigitalKeyRecord?
    fun getAllKeys(): List<DigitalKeyRecord>
    
    // Account-based queries
    fun getKeysByAccount(accountID: String): List<DigitalKeyRecord>
    
    // Synchronization support
    fun updateSyncStatus(keyID: ByteArray, status: SyncStatus)
    fun getPendingSyncKeys(): List<DigitalKeyRecord>

    fun updateTransactionCounter(keyID: ByteArray, counter: Int)
    
    /**
     * Atomic update for Fast Auth Key and Counter.
     */
    fun updateFastKeyAndCounter(keyID: ByteArray, newKey: ByteArray, counter: Int)

    fun deleteKey(keyID: ByteArray)
    fun clearAll()
}

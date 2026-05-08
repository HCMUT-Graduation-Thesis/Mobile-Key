package com.example.a100_basiccrypto.digitalkey.storage

import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.model.SyncStatus
import com.example.a100_basiccrypto.shared.model.VehicleStatus

/**
 * Interface for managing digital key storage.
 */
interface IKeyStorageManager {
    fun saveDigitalKey(record: DigitalKeyRecord)
    fun getDigitalKey(keyID: ByteArray? = null): DigitalKeyRecord?
    fun getAllKeys(): List<DigitalKeyRecord>
    
    // Account-based queries
    fun getKeysByAccount(email: String): List<DigitalKeyRecord>
    
    // Synchronization support
    fun updateSyncStatus(keyID: ByteArray, status: SyncStatus)
    fun getPendingSyncKeys(): List<DigitalKeyRecord>

    fun updateTransactionCounter(keyID: ByteArray, counter: Int)

    /**
     * Updates the last known physical status of the vehicle.
     */
    fun updateVehicleStatus(keyID: ByteArray, status: VehicleStatus)
    
    /**
     * Atomic update for Fast Auth Key and Counter.
     */
    fun updateFastKeyAndCounter(keyID: ByteArray, newKey: ByteArray, counter: Int)

    fun deleteKey(keyID: ByteArray)
    fun clearAll()

    // --- NEW: Pending Revocation Commands for Local Phase ---
    
    /**
     * Adds a friend key to the pending revocation list for a specific vehicle.
     * @param ownerKeyId The ID of the owner key that has authority to revoke.
     * @param friendKeyId The ID of the friend key to be revoked at the vehicle.
     */
    fun addPendingRevocation(ownerKeyId: ByteArray, friendKeyId: ByteArray)

    /**
     * Retrieves all pending revocations for a specific owner key (vehicle).
     */
    fun getPendingRevocations(ownerKeyId: ByteArray): List<ByteArray>

    /**
     * Removes a friend key from the pending revocation list after successful execution at the vehicle.
     */
    fun removePendingRevocation(ownerKeyId: ByteArray, friendKeyId: ByteArray)
}

package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import kotlin.random.Random

/**
 * Handles the logic for creating and receiving Digital Key Invitations.
 * All logs and default metadata strings are in English for consistency.
 */
class SharingManager(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager
) {
    companion object {
        private const val TAG = "SharingManager"
    }

    /**
     * OWNER SIDE: Creates a new invitation (Attestation Package).
     */
    suspend fun createInvitation(
        ownerRecord: DigitalKeyRecord,
        role: Role = Role.FRIEND,
        permissions: Int,
        validityDays: Int
    ): DigitalKeyRecord? {
        return try {
            // 1. Generate 6-digit invitation code
            val invitationCode = (100000 + Random.nextInt(900000)).toString()
            val invCodeHash = CryptoUtils.sha256(invitationCode.toByteArray())

            // 2. Setup Validity
            val now = System.currentTimeMillis() / 1000 // Seconds
            val validTo = if (validityDays > 0) now + (validityDays * 24L * 3600L) else 0L

            // 3. Build Metadata Payload (62 bytes)
            val payload = ByteBuffer.allocate(SharingConstants.METADATA_SIZE).apply {
                put(SharingConstants.AP_VERSION_V1)            // Offset 0
                put(ownerRecord.keyID?.sliceArray(0 until 8) ?: ByteArray(8)) // Offset 1
                put(invCodeHash)                               // Offset 9 (32 bytes)
                put(role.value)                                // Offset 41
                putInt(permissions)                            // Offset 42
                putLong(now)                                   // Offset 46
                putLong(validTo)                               // Offset 54
            }.array()

            // 4. Sign with Owner's Dilithium Private Key
            val ownerSK = ownerRecord.devicePrivateKey ?: return null
            val signature = identityCrypto.sign(payload, ownerSK)
            
            if (signature.isEmpty()) {
                Log.e(TAG, "Failed to sign Attestation Package")
                return null
            }

            // 5. Combine into final Attestation Package (AP)
            val ap = payload + signature
            Log.d(TAG, "AP Created: ${ap.size} bytes. InvCode: $invitationCode")

            // 6. Update Owner's record and upload to Mock Server
            ownerRecord.invitationCode = invitationCode
            ownerRecord.attestationPackage = ap
            
            val success = MockKeyServer.uploadAP(ap)
            if (success) {
                storageManager.saveDigitalKey(ownerRecord)
                ownerRecord
            } else {
                Log.e(TAG, "Failed to upload AP to Mock Server")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating invitation: ${e.message}")
            null
        }
    }

    /**
     * FRIEND SIDE: Processes an incoming AP from the server.
     */
    fun processIncomingInvitation(ap: ByteArray): DigitalKeyRecord? {
        return try {
            if (ap.size < SharingConstants.METADATA_SIZE) {
                Log.e(TAG, "Invalid AP size: ${ap.size}")
                return null
            }

            val buffer = ByteBuffer.wrap(ap)
            
            // Parse metadata for UI/Storage
            val version = buffer.get()
            val parentKeyID = ByteArray(8).apply { buffer.get(this) }
            val invCodeHash = ByteArray(32).apply { buffer.get(this) }
            val roleValue = buffer.get()
            val permissions = buffer.int
            val validFrom = buffer.long
            val validTo = buffer.long

            val newRecord = DigitalKeyRecord().apply {
                this.keyState = KeyState.PROVISIONING 
                this.attestationPackage = ap
                this.invitationCodeHash = invCodeHash
                this.parentKeyID = parentKeyID
                this.role = if (roleValue == Role.OWNER.value) Role.OWNER else Role.FRIEND
                this.permissions = permissions
                this.validityStart = validFrom
                this.validityEnd = validTo
                // Default friendly name in English
                val hexID = parentKeyID.joinToString("") { "%02x".format(it) }.uppercase()
                this.friendlyName = "Shared Key from $hexID"
            }

            storageManager.saveDigitalKey(newRecord)
            Log.i(TAG, "Friend Record created (Version: $version). Pending activation at vehicle.")
            newRecord
        } catch (e: Exception) {
            Log.e(TAG, "Error processing invitation: ${e.message}")
            null
        }
    }
}

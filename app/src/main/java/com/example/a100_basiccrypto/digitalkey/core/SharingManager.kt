package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import kotlin.random.Random

/**
 * Handles the logic for creating and receiving Digital Key Invitations.
 */
class SharingManager(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager
) {
    companion object {
        private const val TAG = "SharingManager"
    }

    /**
     * OWNER SIDE: Creates a new invitation with enhanced constraints (V2).
     */
    suspend fun createInvitation(
        ownerRecord: DigitalKeyRecord,
        role: Role = Role.FRIEND,
        permissions: Int,
        validityDays: Int,
        usageLimit: Int = 0,
        daysOfWeek: Int = 0,
        startTimeMinutes: Int = -1,
        endTimeMinutes: Int = -1
    ): DigitalKeyRecord? {
        return try {
            // 1. Generate 6-digit invitation code
            val invitationCode = (100000 + Random.nextInt(900000)).toString()
            val invCodeHash = CryptoUtils.sha256(invitationCode.toByteArray())

            // 2. Setup Validity Dates
            val now = System.currentTimeMillis() / 1000
            val validTo = if (validityDays > 0) now + (validityDays * 24L * 3600L) else 0L

            // 3. Build Metadata Payload V2 (68 bytes)
            val payload = ByteBuffer.allocate(SharingConstants.METADATA_SIZE).apply {
                put(SharingConstants.AP_VERSION_V2)              // Offset 0
                put(ownerRecord.keyID?.sliceArray(0 until 8) ?: ByteArray(8)) // Offset 1
                put(invCodeHash)                                 // Offset 9
                put(role.value)                                  // Offset 41
                putInt(permissions)                              // Offset 42
                putLong(now)                                     // Offset 46
                putLong(validTo)                                 // Offset 54
                
                // New Fields V2
                put(usageLimit.toByte())                         // Offset 62
                put(daysOfWeek.toByte())                         // Offset 63
                putShort(startTimeMinutes.toShort())             // Offset 64
                putShort(endTimeMinutes.toShort())               // Offset 66
            }.array()

            // 4. Sign with Owner's Dilithium Private Key
            val ownerSK = ownerRecord.devicePrivateKey ?: return null
            val signature = identityCrypto.sign(payload, ownerSK)
            
            if (signature.isEmpty()) return null

            val ap = payload + signature

            // 5. Update Owner's temporary record
            ownerRecord.invitationCode = invitationCode
            ownerRecord.attestationPackage = ap
            
            // Sync fields for reference on Owner device
            ownerRecord.usageLimit = usageLimit
            ownerRecord.daysOfWeek = daysOfWeek
            ownerRecord.startTimeMinutes = startTimeMinutes
            ownerRecord.endTimeMinutes = endTimeMinutes
            
            if (MockKeyServer.uploadAP(ap)) {
                storageManager.saveDigitalKey(ownerRecord)
                ownerRecord
            } else null
        } catch (e: Exception) {
            Log.e(TAG, "Error creating invitation: ${e.message}")
            null
        }
    }

    /**
     * FRIEND SIDE: Processes an incoming AP V2.
     */
    fun processIncomingInvitation(ap: ByteArray): DigitalKeyRecord? {
        return try {
            if (ap.size < SharingConstants.METADATA_SIZE) return null

            val buffer = ByteBuffer.wrap(ap)
            val version = buffer.get()
            val parentKeyID = ByteArray(8).apply { buffer.get(this) }
            val invCodeHash = ByteArray(32).apply { buffer.get(this) }
            val roleValue = buffer.get()
            val permissions = buffer.int
            val validFrom = buffer.long
            val validTo = buffer.long
            
            var usageLimit = 0
            var daysOfWeek = 0
            var startM = -1
            var endM = -1

            if (version >= 0x02) {
                usageLimit = buffer.get().toInt()
                daysOfWeek = buffer.get().toInt()
                startM = buffer.short.toInt()
                endM = buffer.short.toInt()
            }

            val newRecord = DigitalKeyRecord().apply {
                this.keyState = KeyState.PROVISIONING 
                this.attestationPackage = ap
                this.invitationCodeHash = invCodeHash
                this.parentKeyID = parentKeyID
                this.role = if (roleValue == Role.OWNER.value) Role.OWNER else Role.FRIEND
                this.permissions = permissions
                this.validityStart = validFrom
                this.validityEnd = validTo
                
                // New Fields
                this.usageLimit = usageLimit
                this.daysOfWeek = daysOfWeek
                this.startTimeMinutes = startM
                this.endTimeMinutes = endM
                
                val hexID = parentKeyID.joinToString("") { "%02x".format(it) }.uppercase()
                this.friendlyName = "Shared Key from $hexID"
            }

            storageManager.saveDigitalKey(newRecord)
            newRecord
        } catch (e: Exception) {
            Log.e(TAG, "Error processing invitation: ${e.message}")
            null
        }
    }
}

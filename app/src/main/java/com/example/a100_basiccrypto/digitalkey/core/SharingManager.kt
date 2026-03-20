package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants
import com.example.a100_basiccrypto.shared.command.SharingConstants
import com.example.a100_basiccrypto.shared.model.Role
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.CoreDigitalKey
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
        endTimeMinutes: Int = -1,
        friendlyName: String = ""
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
                put(ownerRecord.core.keyID?.sliceArray(0 until 8) ?: ByteArray(8)) // Offset 1
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

            // 5. Create PENDING record for Owner to track
            val pendingRecord = DigitalKeyRecord().apply {
                core.keyID = CryptoUtils.sha256(ap).sliceArray(0 until 16) // Temp ID
                core.parentKeyID = ownerRecord.core.keyID?.sliceArray(0 until 8)
                core.keyState = KeyState.PENDING
                core.role = role
                core.permissions = permissions
                core.usageLimit = usageLimit
                core.daysOfWeek = daysOfWeek
                core.startTimeMinutes = startTimeMinutes
                core.endTimeMinutes = endTimeMinutes
                core.carMetadata = ownerRecord.core.carMetadata
                
                this.invitationCode = invitationCode
                this.invitationCodeHash = invCodeHash
                this.attestationPackage = ap
                this.friendlyName = if(friendlyName.isNotEmpty()) friendlyName else "Guest Key (Pending)"
            }
            
            if (MockKeyServer.uploadAP(ap)) {
                storageManager.saveDigitalKey(pendingRecord)
                pendingRecord
            } else null
        } catch (e: Exception) {
            Log.e(TAG, "Error creating invitation: ${e.message}")
            null
        }
    }

    /**
     * FRIEND SIDE: Processes an incoming AP V2.
     * Note: This only PARSES the AP, it does NOT save it to storage yet.
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
                core.keyID = CryptoUtils.sha256(ap).sliceArray(0 until 16)
                core.keyState = KeyState.PROVISIONING 
                core.parentKeyID = parentKeyID
                core.role = if (roleValue == Role.OWNER.value) Role.OWNER else Role.FRIEND
                core.permissions = permissions
                core.validityStart = validFrom
                core.validityEnd = validTo
                core.usageLimit = usageLimit
                core.daysOfWeek = daysOfWeek
                core.startTimeMinutes = startM
                core.endTimeMinutes = endM
                
                this.attestationPackage = ap
                this.invitationCodeHash = invCodeHash
                
                val hexID = parentKeyID.joinToString("") { "%02x".format(it) }.uppercase()
                this.friendlyName = "Shared Key from $hexID"
            }
            return newRecord
        } catch (e: Exception) {
            Log.e(TAG, "Error processing invitation: ${e.message}")
            null
        }
    }

    /**
     * Call this ONLY after the user has successfully entered the Invitation Code.
     */
    fun finalizeProvisioning(record: DigitalKeyRecord) {
        record.core.keyState = KeyState.ACTIVE
        storageManager.saveDigitalKey(record)
    }
}

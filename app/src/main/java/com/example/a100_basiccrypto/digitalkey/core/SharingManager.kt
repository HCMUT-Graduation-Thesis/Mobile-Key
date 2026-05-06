package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.model.Role
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.AttestationMetadata
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
     * OWNER SIDE: Creates a new invitation using AttestationMetadata.
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
        holderNickname: String = "", // Holder Name from UI (e.g. "Friend A")
        recipientEmail: String = "", 
        senderName: String = "Owner"
    ): DigitalKeyRecord? {
        return try {
            // 1. Generate 6-digit invitation code (PIN)
            val invitationCode = (100000 + Random.nextInt(900000)).toString()
            
            // Use Owner's KeyID as salt for HMAC
            val ownerID = ownerRecord.core.keyID?.sliceArray(0 until 8) ?: ByteArray(8)
            val invCodeHash = CryptoUtils.hmacSha256(ownerID, invitationCode.toByteArray())

            // 2. Setup Validity Dates
            val now = System.currentTimeMillis() / 1000
            val validTo = if (validityDays > 0) now + (validityDays * 24L * 3600L) else 0L

            // 3. Build Metadata object
            val metadata = AttestationMetadata(
                parentKeyID = ownerID,
                invCodeHash = invCodeHash,
                role = role,
                permissions = permissions,
                validFrom = now,
                validTo = validTo,
                usageLimit = usageLimit,
                daysOfWeek = daysOfWeek,
                startTimeMinutes = startTimeMinutes,
                endTimeMinutes = endTimeMinutes
            )

            val payload = metadata.toByteArray()

            // 4. Sign with Owner's Dilithium Private Key
            val ownerSK = ownerRecord.devicePrivateKey ?: return null
            val signature = identityCrypto.sign(payload, ownerSK)
            
            if (signature.isEmpty()) return null

            // AP = Metadata (68b) + Signature
            val ap = payload + signature

            // 5. Create PENDING record for Owner to track
            val pendingRecord = DigitalKeyRecord().apply {
                // FIXED: Use 8 bytes for consistency with Owner Pairing
                core.keyID = CryptoUtils.sha256(ap).sliceArray(0 until 8)
                core.parentKeyID = ownerID
                core.keyState = KeyState.PENDING
                core.role = role
                core.permissions = permissions
                core.usageLimit = usageLimit
                core.daysOfWeek = daysOfWeek
                core.startTimeMinutes = startTimeMinutes
                core.endTimeMinutes = endTimeMinutes
                
                // Set the correct identities
                this.carMetadata = ownerRecord.carMetadata
                this.friendlyName = ownerRecord.friendlyName // Car's name
                this.keyHolderName = holderNickname.ifEmpty { "Guest Key" } // User's nickname
                
                this.invitationCode = invitationCode
                this.invitationCodeHash = invCodeHash
                this.attestationPackage = ap
                this.accountEmail = recipientEmail
                this.moduleID = ownerRecord.moduleID // FIX Mid=null
            }
            
            // Build the invitation package for the server
            val invitation = ShareInvitation(
                ap = ap,
                friendlyName = ownerRecord.friendlyName, // Passing car's name for compatibility
                holderNickname = pendingRecord.keyHolderName, // Passing user's nickname
                recipientEmail = recipientEmail,
                senderName = senderName,
                senderEmail = ownerRecord.accountEmail ?: "",
                moduleID = ownerRecord.moduleID // FIX Mid=null
            )

            if (MockKeyServer.uploadInvitation(invitation)) {
                storageManager.saveDigitalKey(pendingRecord)
                pendingRecord
            } else null
        } catch (e: Exception) {
            Log.e(TAG, "Error creating invitation: ${e.message}")
            null
        }
    }

    /**
     * FRIEND SIDE: Processes an incoming AP using AttestationMetadata.
     */
    fun processIncomingInvitation(invitation: ShareInvitation): DigitalKeyRecord? {
        return try {
            val ap = invitation.ap
            if (ap.size < AttestationMetadata.METADATA_SIZE) return null

            val metadataBytes = ap.sliceArray(0 until AttestationMetadata.METADATA_SIZE)
            val metadata = AttestationMetadata.fromByteArray(metadataBytes)

            val newRecord = DigitalKeyRecord().apply {
                core.keyID = CryptoUtils.sha256(ap).sliceArray(0 until 8)
                core.keyState = KeyState.PENDING
                core.parentKeyID = metadata.parentKeyID
                core.role = metadata.role
                core.permissions = metadata.permissions
                core.validityStart = metadata.validFrom
                core.validityEnd = metadata.validTo
                core.usageLimit = metadata.usageLimit
                core.daysOfWeek = metadata.daysOfWeek
                core.startTimeMinutes = metadata.startTimeMinutes
                core.endTimeMinutes = metadata.endTimeMinutes
                
                this.attestationPackage = ap
                this.invitationCodeHash = metadata.invCodeHash
                this.accountEmail = invitation.recipientEmail
                
                // Map identities from Server
                this.carMetadata = invitation.carMetadata
                this.friendlyName = invitation.friendlyName // Map car name
                this.keyHolderName = invitation.holderNickname // Map user nickname
                this.moduleID = invitation.moduleID // FIX Mid=null
            }
            return newRecord
        } catch (e: Exception) {
            Log.e(TAG, "Error processing invitation: ${e.message}")
            null
        }
    }

    /**
     * Finalize Stage 1 after successful PIN entry.
     */
    fun verifyPinAndFinalize(record: DigitalKeyRecord, enteredPin: String): Boolean {
        val ownerID = record.core.parentKeyID ?: return false
        val computedHash = CryptoUtils.hmacSha256(ownerID, enteredPin.toByteArray())
        
        return if (computedHash.contentEquals(record.invitationCodeHash)) {
            record.core.keyState = KeyState.PROVISIONING
            record.invitationCode = enteredPin
            storageManager.saveDigitalKey(record)
            true
        } else {
            false
        }
    }
}

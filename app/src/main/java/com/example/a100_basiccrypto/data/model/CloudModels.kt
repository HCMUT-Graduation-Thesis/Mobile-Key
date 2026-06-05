package com.example.a100_basiccrypto.data.model

import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role

/**
 * 1. Cloud User Profile
 * Manages personal information and account status.
 */
data class CloudUserProfile(
    val email: String,               // Unique identifier
    val displayName: String,         // Name to show in UI
    val password: String,            // Plain text password for mock auth
    val lastLoginAt: Long = 0L,
    val fcmToken: String? = null     // Token for Push Notifications
)

/**
 * Possible outcomes of an invitation after interaction.
 */
enum class InvitationStatus {
    CLAIMED,    // Success: PIN was correct
    FAILED,     // Failure: Too many wrong PIN attempts
    REVOKED     // Cancelled by Owner
}

/**
 * Status update payload sent back to the Owner.
 */
data class InvitationStatusUpdate(
    val ap: ByteArray,
    val status: InvitationStatus,
    val recipientEmail: String,
    val message: String = ""
)

/**
 * Data wrapper for a Key Invitation. 
 */
data class ShareInvitation(
    val ap: ByteArray,
    val friendlyName: String,         // Car's Friendly Name (legacy compatibility)
    val holderNickname: String = "", // NEW: Specific field for the holder's name
    val recipientEmail: String = "", 
    val senderName: String = "Owner",
    val senderEmail: String = "",    
    var carMetadata: CarMetadata? = null,
    val moduleID: ByteArray? = null   // Added to fix Mid=null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ShareInvitation
        return ap.contentEquals(other.ap) && recipientEmail == other.recipientEmail
    }

    override fun hashCode(): Int {
        var result = ap.contentHashCode()
        result = 31 * result + recipientEmail.hashCode()
        return result
    }
}

/**
 * 2. Cloud Key Record
 */
data class CloudKeyRecord(
    val keyId: String,
    val moduleID: String,
    val ownerEmail: String,
    val holderEmail: String,
    val holderNickname: String = "",
    val parentKeyId: String? = null,
    val devicePublicKey: String,
    val vehiclePublicKey: String,
    val role: Role,
    val permissions: Int,
    val keyState: KeyState,
    val validityStart: Long,
    val validityEnd: Long,
    val usageLimit: Int,
    val friendlyName: String,        
    val metadata: CarMetadata,       
    val lastSyncedAt: Long = System.currentTimeMillis()
)

package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.UUID

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

/**
 * Mock Server to simulate User Authentication, Key Sharing, and Cloud Sync.
 */
object MockKeyServer {
    private const val TAG = "MockKeyServer"

    private val userDatabase = mutableMapOf<String, CloudUserProfile>().apply {
        put("test@gmail.com", CloudUserProfile("test@gmail.com", "Owner User", "123456"))
        put("test2@gmail.com", CloudUserProfile("test2@gmail.com", "Friend User", "123456"))
    }
    
    private val userKeyCloud = mutableMapOf<String, MutableList<CloudKeyRecord>>()
    private val invitationInbox = mutableMapOf<String, MutableList<ShareInvitation>>()
    private val onlineUsers = mutableSetOf<String>()
    
    private val _invitationFlow = MutableSharedFlow<ShareInvitation>(replay = 0)
    val invitationFlow = _invitationFlow.asSharedFlow()
    
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val activationFlow = _activationFlow.asSharedFlow()

    private val _statusUpdateFlow = MutableSharedFlow<InvitationStatusUpdate>(replay = 0)
    val statusUpdateFlow = _statusUpdateFlow.asSharedFlow()

    fun setOnline(email: String) {
        onlineUsers.add(email)
        Log.i(TAG, "📱 [SERVER] User $email is now ONLINE")
    }

    fun setOffline(email: String) {
        onlineUsers.remove(email)
        Log.i(TAG, "📱 [SERVER] User $email is now OFFLINE")
    }

    suspend fun login(email: String, pass: String): AuthManager.UserProfile? {
        delay(1000)
        val user = userDatabase[email]
        if (user != null && user.password == pass) {
            setOnline(email)
            Log.d(TAG, "🔑 [AUTH] User $email logged in successfully.")
            return AuthManager.UserProfile(
                email = email,
                displayName = user.displayName,
                token = "mock_jwt_" + UUID.randomUUID().toString().take(8)
            )
        }
        Log.w(TAG, "❌ [AUTH] Login failed for user: $email")
        return null
    }

    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean {
        delay(800)
        if (userDatabase.containsKey(email)) return false
        val name = if (displayName.isNotEmpty()) displayName else email.substringBefore("@")
        userDatabase[email] = CloudUserProfile(email, name, pass)
        Log.i(TAG, "👤 [AUTH] New user registered: $email")
        return true
    }

    // --- SHARING METHODS ---

    /**
     * OWNER SIDE: Pre-check before sending an invitation.
     */
    suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String? {
        delay(500)
        Log.d(TAG, "🛡️ [LEGALITY] Checking: $senderEmail -> $recipientEmail for Car: $parentKeyIdHex")
        
        if (senderEmail.equals(recipientEmail, ignoreCase = true)) {
            Log.e(TAG, "🚫 [LEGALITY] DENIED: User $senderEmail tried to share with themselves.")
            return "You cannot share a key with yourself."
        }
        
        if (!userDatabase.containsKey(recipientEmail)) {
            Log.w(TAG, "🚫 [LEGALITY] DENIED: Recipient $recipientEmail does not exist.")
            return "Recipient account does not exist."
        }
        
        val pending = invitationInbox[recipientEmail] ?: emptyList<ShareInvitation>()
        if (pending.any { inv ->
            // FIX: AP structure is [Version(1b) | ParentID(8b) | ...] -> ParentID is at index 1 to 9
            val invParentId = inv.ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            invParentId == parentKeyIdHex
        }) {
            Log.w(TAG, "🚫 [LEGALITY] DENIED: Car $parentKeyIdHex already has a pending invitation for $recipientEmail.")
            return "An invitation for this vehicle is already pending for this recipient."
        }
        
        Log.i(TAG, "✅ [LEGALITY] PASSED for $recipientEmail")
        return null
    }

    /**
     * Owner uploads invitation.
     */
    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "☁️ [UPLOAD] Processing Invitation from ${invitation.senderEmail} to ${invitation.recipientEmail}")
        delay(1000)

        // 1. Proactively attach car metadata
        val ap = invitation.ap
        if (invitation.carMetadata == null && ap.size >= 9) {
            // FIX: Correct offset for Parent KeyID in AP package is 1 to 9 (Version is at index 0)
            val parentKeyIdHex = ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            val foundMetadata = userKeyCloud.values.flatten()
                .find { it.keyId == parentKeyIdHex }?.metadata
            
            if (foundMetadata != null) {
                invitation.carMetadata = foundMetadata
                Log.d(TAG, "📦 [UPLOAD] Attached car metadata to invitation: ${foundMetadata.modelName} (Plate: ${foundMetadata.licensePlate})")
            } else {
                Log.w(TAG, "⚠️ [UPLOAD] Metadata NOT found for Parent KeyID: $parentKeyIdHex. Checking fallback...")
                // Fallback: search by prefix if the ID was stored differently
                val fallbackMetadata = userKeyCloud.values.flatten()
                    .find { it.keyId.startsWith(parentKeyIdHex) }?.metadata
                if (fallbackMetadata != null) {
                    invitation.carMetadata = fallbackMetadata
                    Log.d(TAG, "📦 [UPLOAD] Attached car metadata via prefix fallback: ${fallbackMetadata.licensePlate}")
                } else {
                    Log.w(TAG, "❌ [UPLOAD] Metadata truly NOT found for Parent KeyID: $parentKeyIdHex. Friend will see 'N/A'.")
                }
            }
        }

        // 2. SAVE TO INBOX
        val inbox = invitationInbox.getOrPut(invitation.recipientEmail) { mutableListOf() }
        inbox.add(invitation)
        Log.i(TAG, "📩 [INBOX] Invitation stored in ${invitation.recipientEmail}'s inbox. Total pending: ${inbox.size}")

        // 3. Push if online
        if (onlineUsers.contains(invitation.recipientEmail)) {
            Log.i(TAG, "🚀 [PUSH] Recipient ${invitation.recipientEmail} is ONLINE. Emitting real-time invitation.")
            _invitationFlow.emit(invitation)
        } else {
            Log.d(TAG, "💤 [PUSH] Recipient ${invitation.recipientEmail} is OFFLINE. Invitation stays in Inbox.")
        }
        return true
    }

    /**
     * OWNER SIDE: Revokes an active or pending invitation.
     */
    suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray) {
        Log.i(TAG, "🛡️ [SERVER] Owner $senderEmail is revoking key for $recipientEmail")
        delay(500)
        
        // 1. Remove from Inbox (Status: PENDING)
        val removedFromInbox = invitationInbox[recipientEmail]?.removeAll { it.ap.contentEquals(ap) } ?: false
        if (removedFromInbox) {
            Log.d(TAG, "🗑️ [INBOX] Removed invitation from $recipientEmail's inbox.")
        }

        // 2. Synchronization: Remove from Cloud Key Records
        if (ap.size >= 9) {
            // FIX: Correct offset 1 to 9
            val parentKeyIdHex = ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            userKeyCloud[recipientEmail]?.removeAll { it.parentKeyId == parentKeyIdHex || it.ownerEmail == senderEmail }
            userKeyCloud[senderEmail]?.removeAll { it.holderEmail == recipientEmail && it.parentKeyId == parentKeyIdHex }
            Log.d(TAG, "☁️ [SYNC] Revoked key records for $parentKeyIdHex removed from Cloud storage.")
        }

        // 3. Notify Friend
        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, InvitationStatus.REVOKED, recipientEmail))
        Log.d(TAG, "🔔 [STATUS] REVOKED status update emitted to parties.")
    }

    /**
     * FRIEND SIDE: Reports the outcome back to the server.
     */
    suspend fun reportInvitationOutcome(recipientEmail: String, ap: ByteArray, status: InvitationStatus, senderEmail: String) {
        Log.i(TAG, "📣 [OUTCOME] User $recipientEmail reported: $status. Notifying Owner: $senderEmail")
        
        when (status) {
            InvitationStatus.CLAIMED -> Log.d(TAG, "🔄 [STATUS] Key transition: PENDING -> PROVISIONING for $recipientEmail")
            InvitationStatus.FAILED -> Log.w(TAG, "❌ [STATUS] Key sharing failed for $recipientEmail (Invalid PIN attempts)")
            else -> {}
        }

        val removed = invitationInbox[recipientEmail]?.removeAll { it.ap.contentEquals(ap) } ?: false
        if (removed) {
            Log.d(TAG, "🗑️ [INBOX] Cleaned up AP from $recipientEmail's inbox.")
        }

        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, status, recipientEmail))
        Log.d(TAG, "🔔 [STATUS] Update emitted for Owner $senderEmail.")
    }

    suspend fun fetchPendingInvitations(email: String): List<ShareInvitation> {
        delay(800)
        val pending = invitationInbox[email] ?: emptyList<ShareInvitation>()
        Log.i(TAG, "📥 [FETCH] User $email retrieved ${pending.size} pending invitations from Inbox.")
        return pending
    }

    fun removeInvitation(email: String, ap: ByteArray) {
        val inbox = invitationInbox[email] ?: return
        if (inbox.removeAll { it.ap.contentEquals(ap) }) {
            Log.d(TAG, "🗑️ [INBOX] Manual removal of AP for $email.")
        }
    }

    suspend fun notifyActivation(ap: ByteArray) {
        Log.i(TAG, "⚡ [ACTIVATE] Signaling key activation (PROVISIONING -> ACTIVE).")
        _activationFlow.emit(ap)
    }

    // --- CLOUD SYNC ---

    suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        val keys = userKeyCloud.getOrPut(email) { mutableListOf() }
        keys.removeAll { it.keyId == record.keyId || it.moduleID == record.moduleID }
        keys.add(record)
        
        // Detailed log of Car Metadata on Cloud
        Log.i(TAG, "☁️ [SYNC] NEW Car Metadata synced to Cloud for user: $email")
        Log.d(TAG, "   └─ Car: ${record.friendlyName} (Model: ${record.metadata.modelName})")
        Log.d(TAG, "   └─ Plate: ${record.metadata.licensePlate}")
        Log.d(TAG, "   └─ VIN/ModuleID: ${record.moduleID}")
        Log.d(TAG, "   └─ Holder: ${record.holderNickname} (Role: ${record.role})")

        return true
    }

    suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return userKeyCloud[email] ?: emptyList()
    }

    fun reset() {
        Log.w(TAG, "⚠️ [SERVER] Mock Server RESET initiated.")
        onlineUsers.clear()
        userKeyCloud.clear()
        invitationInbox.clear()
    }
}

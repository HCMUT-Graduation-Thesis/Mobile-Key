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
 * Data wrapper for a Key Invitation. 
 * Updated to include recipientEmail and proactive carMetadata.
 */
data class ShareInvitation(
    val ap: ByteArray,
    val friendlyName: String,
    val recipientEmail: String = "", // Matches the account identifier
    val senderName: String = "Owner",
    val senderEmail: String = "",    // Added to track who sent it
    var carMetadata: CarMetadata? = null 
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
 * Enhanced Metadata stored on the cloud for each key, optimized for management and sharing.
 */
data class CloudKeyRecord(
    val keyId: String,               // Local unique ID (Hex)
    val moduleID: String,            // Vehicle Hardware ID (Hex/VIN)
    val ownerEmail: String,          // Email of the original vehicle owner
    val holderEmail: String,         // Email of the person currently holding this key
    val parentKeyId: String? = null, // ID of the parent key that granted this one (null for Owner)
    val devicePublicKey: String,     // Phone's Dilithium PK (Hex)
    val vehiclePublicKey: String,    // Vehicle's Dilithium PK (Hex)
    val role: Role,                  // OWNER / FRIEND
    val permissions: Int,            // Bitmask
    val keyState: KeyState,          // ACTIVE, REVOKED, etc.
    val validityStart: Long,
    val validityEnd: Long,
    val usageLimit: Int,
    val friendlyName: String,        // User-defined name for the car
    val metadata: CarMetadata,       // Brand, Plate, Color, etc.
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
    
    // INBOX: Stores invitations for users, ensuring they don't get lost when offline
    private val invitationInbox = mutableMapOf<String, MutableList<ShareInvitation>>()

    // --- SESSION & PUSH ---
    private val onlineUsers = mutableSetOf<String>()
    private val _invitationFlow = MutableSharedFlow<ShareInvitation>(replay = 0)
    val invitationFlow = _invitationFlow.asSharedFlow()
    
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val activationFlow = _activationFlow.asSharedFlow()

    // --- AUTH METHODS ---

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
            return AuthManager.UserProfile(
                email = email,
                displayName = user.displayName,
                token = "mock_jwt_" + UUID.randomUUID().toString().take(8)
            )
        }
        return null
    }

    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean {
        delay(800)
        if (userDatabase.containsKey(email)) return false
        val name = if (displayName.isNotEmpty()) displayName else email.substringBefore("@")
        userDatabase[email] = CloudUserProfile(email, name, pass)
        return true
    }

    // --- SHARING METHODS ---

    /**
     * OWNER SIDE: Pre-check before sending an invitation.
     * Checks for: self-sharing, recipient existence, and duplicate invitations.
     */
    suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String? {
        delay(500)
        if (senderEmail == recipientEmail) return "You cannot share a key with yourself."
        if (!userDatabase.containsKey(recipientEmail)) return "Recipient account does not exist."
        
        // Check if an invitation for this car to this recipient is already pending in the inbox
        val pending = invitationInbox[recipientEmail] ?: emptyList<ShareInvitation>()
        val isDuplicate = pending.any { inv ->
            val invParentId = inv.ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            invParentId == parentKeyIdHex
        }
        if (isDuplicate) return "An invitation for this vehicle is already pending for this recipient."
        
        return null // All good
    }

    /**
     * Owner uploads invitation. Server saves to Inbox and pushes if online.
     */
    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "☁️ [SERVER] Processing Invitation for: ${invitation.recipientEmail}")
        delay(1000)

        // 1. Proactively attach car metadata
        val ap = invitation.ap
        if (invitation.carMetadata == null && ap.size >= 9) {
            val parentKeyIdHex = ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            val foundMetadata = userKeyCloud.values.flatten()
                .find { it.keyId.startsWith(parentKeyIdHex) }?.metadata
            
            if (foundMetadata != null) {
                invitation.carMetadata = foundMetadata
            }
        }

        // 2. SAVE TO INBOX (Crucial for Offline Support)
        val inbox = invitationInbox.getOrPut(invitation.recipientEmail) { mutableListOf() }
        inbox.add(invitation)
        Log.i(TAG, "📦 [SERVER] Invitation saved to ${invitation.recipientEmail}'s inbox. Count: ${inbox.size}")

        // 3. Emit for real-time push if online
        if (onlineUsers.contains(invitation.recipientEmail)) {
            Log.i(TAG, "🚀 [SERVER] Recipient is ONLINE. Pushing notification...")
            _invitationFlow.emit(invitation)
        }
        return true
    }

    /**
     * FRIEND SIDE: Fetch all pending invitations from the inbox (called on login/refresh).
     */
    suspend fun fetchPendingInvitations(email: String): List<ShareInvitation> {
        delay(800)
        val pending = invitationInbox[email] ?: emptyList<ShareInvitation>()
        Log.i(TAG, "📩 [SERVER] User $email fetched ${pending.size} pending invitations.")
        return pending
    }

    /**
     * FRIEND SIDE: Remove invitation from inbox after successful claim/PIN entry.
     */
    fun removeInvitation(email: String, ap: ByteArray) {
        val inbox = invitationInbox[email] ?: return
        inbox.removeAll { it.ap.contentEquals(ap) }
        Log.d(TAG, "🗑️ [SERVER] Removed invitation from $email's inbox after claim.")
    }

    suspend fun notifyActivation(ap: ByteArray) {
        _activationFlow.emit(ap)
    }

    // --- CLOUD SYNC ---

    suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        val keys = userKeyCloud.getOrPut(email) { mutableListOf() }
        keys.removeAll { it.keyId == record.keyId || it.moduleID == record.moduleID }
        keys.add(record)
        return true
    }

    suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return userKeyCloud[email] ?: emptyList()
    }

    fun reset() {
        onlineUsers.clear()
        userKeyCloud.clear()
        invitationInbox.clear()
    }
}

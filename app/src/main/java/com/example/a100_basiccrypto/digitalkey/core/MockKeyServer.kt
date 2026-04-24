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
    val recipientEmail: String = "", // Changed from 'recipient' for account consistency
    val senderName: String = "Owner",
    var carMetadata: CarMetadata? = null 
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ShareInvitation
        return ap.contentEquals(other.ap) && friendlyName == other.friendlyName && recipientEmail == other.recipientEmail
    }

    override fun hashCode(): Int {
        var result = ap.contentHashCode()
        result = 31 * result + friendlyName.hashCode()
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
    
    // Ownership & Genealogy for Sharing Management
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

    // --- SESSION & PUSH ---
    private val onlineUsers = mutableSetOf<String>()
    private val _invitationFlow = MutableSharedFlow<ShareInvitation>(replay = 0)
    val invitationFlow = _invitationFlow.asSharedFlow()
    
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val activationFlow = _activationFlow.asSharedFlow()

    // --- AUTH METHODS ---

    /**
     * Mark a user as online to receive push notifications.
     */
    fun setOnline(email: String) {
        onlineUsers.add(email)
        Log.i(TAG, "📱 [SERVER] User $email is now ONLINE")
    }

    /**
     * Mark a user as offline to stop receiving push notifications.
     */
    fun setOffline(email: String) {
        onlineUsers.remove(email)
        Log.i(TAG, "📱 [SERVER] User $email is now OFFLINE")
    }

    suspend fun login(email: String, pass: String): AuthManager.UserProfile? {
        delay(1000)
        val user = userDatabase[email]
        if (user != null && user.password == pass) {
            setOnline(email) // Mark user as online
            return AuthManager.UserProfile(
                email = email,
                displayName = user.displayName,
                token = "mock_jwt_" + UUID.randomUUID().toString().take(8)
            )
        }
        return null
    }

    /**
     * Register a new user on the mock server.
     */
    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean {
        Log.d(TAG, "☁️ [SERVER] Registering user: $email")
        delay(800)
        if (userDatabase.containsKey(email)) {
            Log.e(TAG, "❌ [SERVER] Registration failed: Email $email already exists.")
            return false
        }
        val name = if (displayName.isNotEmpty()) displayName else email.substringBefore("@")
        userDatabase[email] = CloudUserProfile(email, name, pass)
        Log.i(TAG, "✅ [SERVER] User registered successfully: $email")
        return true
    }

    // --- SHARING METHODS ---

    /**
     * Owner uploads invitation. Server attaches CarMetadata and pushes to Friend if online.
     */
    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "☁️ [SERVER] Processing Invitation for: ${invitation.recipientEmail}")
        delay(1000)

        // 1. Proactively attach car metadata by looking up the Parent Key ID in the AP
        val ap = invitation.ap
        if (invitation.carMetadata == null && ap.size >= 9) {
            // Extract ParentKeyID from AP (Offset 1 to 9)
            val parentKeyIdHex = ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            
            // Search all cloud records for the matching parent key
            val foundMetadata = userKeyCloud.values.flatten()
                .find { it.keyId.startsWith(parentKeyIdHex) }?.metadata
            
            if (foundMetadata != null) {
                invitation.carMetadata = foundMetadata
                Log.i(TAG, "☁️ [SERVER] Proactively attached CarMetadata for: ${foundMetadata.modelName}")
            }
        }

        // 2. Check if Friend is online to "Push" the invitation
        if (onlineUsers.contains(invitation.recipientEmail)) {
            Log.i(TAG, "🚀 [SERVER] Friend is ONLINE. Pushing invitation immediately...")
            _invitationFlow.emit(invitation)
            return true
        } else {
            Log.w(TAG, "⌛ [SERVER] Friend is OFFLINE. Invitation stored (Mocked).")
            return false
        }
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
    }
}

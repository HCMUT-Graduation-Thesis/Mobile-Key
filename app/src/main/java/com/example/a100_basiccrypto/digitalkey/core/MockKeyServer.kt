package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import com.example.a100_basiccrypto.shared.model.CarMetadata
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.UUID

/**
 * Data wrapper for a Key Invitation to include UI metadata without changing the AP.
 */
data class ShareInvitation(
    val ap: ByteArray,
    val friendlyName: String,
    val recipient: String = "",
    val senderName: String = "Owner",
    val carMetadata: CarMetadata? = null 
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ShareInvitation
        return ap.contentEquals(other.ap) && friendlyName == other.friendlyName && recipient == other.recipient
    }

    override fun hashCode(): Int {
        var result = ap.contentHashCode()
        result = 31 * result + friendlyName.hashCode()
        result = 31 * result + recipient.hashCode()
        return result
    }
}

/**
 * Metadata stored on the cloud for each key.
 */
data class CloudKeyRecord(
    val keyId: String,
    val metadata: CarMetadata
)

/**
 * Mock Server to simulate User Authentication, Key Sharing, and Cloud Sync.
 */
object MockKeyServer {
    private const val TAG = "MockKeyServer"

    // --- AUTH STORAGE ---
    // Pre-populate with two test accounts for easier multi-user testing
    private val userDatabase = mutableMapOf<String, String>().apply {
        put("test@gmail.com", "123456")
        put("test2@gmail.com", "123456")
    }
    
    // Maps Token to a list of CloudKeyRecords
    private val userKeyCloud = mutableMapOf<String, MutableList<CloudKeyRecord>>()

    // --- SHARING STORAGE ---
    private var pendingInvitation: ShareInvitation? = null
    private val _invitationFlow = MutableSharedFlow<ShareInvitation>(replay = 0)
    val invitationFlow = _invitationFlow.asSharedFlow()
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val activationFlow = _activationFlow.asSharedFlow()

    // --- AUTH & CLOUD METHODS ---

    suspend fun register(email: String, pass: String): Boolean {
        Log.d(TAG, "Registering user: $email")
        delay(800)
        if (userDatabase.containsKey(email)) return false
        userDatabase[email] = pass
        return true
    }

    suspend fun login(email: String, pass: String): AuthManager.UserProfile? {
        Log.d(TAG, "Login attempt: $email")
        delay(1000)
        if (userDatabase[email] == pass) {
            return AuthManager.UserProfile(
                email = email,
                displayName = email.substringBefore("@").replaceFirstChar { it.uppercase() },
                token = "mock_jwt_" + UUID.randomUUID().toString().take(8)
            )
        }
        return null
    }

    /**
     * Synchronizes key metadata to the user's cloud account after successful pairing.
     */
    suspend fun syncKeyToCloud(token: String, keyId: String, metadata: CarMetadata): Boolean {
        Log.d(TAG, "Syncing Key [$keyId] to cloud for token [$token]...")
        delay(1200)
        
        val keys = userKeyCloud.getOrPut(token) { mutableListOf() }
        keys.removeAll { it.keyId == keyId }
        keys.add(CloudKeyRecord(keyId, metadata))
        
        Log.i(TAG, "Cloud Sync Complete for vehicle: ${metadata.modelName}. Total keys for this session: ${keys.size}")
        return true
    }

    suspend fun fetchUserKeys(token: String): List<CloudKeyRecord> {
        Log.d(TAG, "Fetching all keys for token: $token")
        delay(1000)
        return userKeyCloud[token] ?: emptyList()
    }

    // --- SHARING METHODS ---

    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "Uploading Invitation to Mock Server for ${invitation.recipient}...")
        delay(1000)
        pendingInvitation = invitation
        _invitationFlow.emit(invitation)
        return true
    }

    suspend fun downloadInvitation(): ShareInvitation? {
        Log.d(TAG, "Checking for invitations on Mock Server...")
        delay(500)
        return pendingInvitation
    }

    suspend fun notifyActivation(ap: ByteArray) {
        Log.d(TAG, "Notifying Owner of Key Activation...")
        delay(500)
        _activationFlow.emit(ap)
    }

    /**
     * Clears session data but keeps core test accounts.
     */
    fun reset() {
        pendingInvitation = null
        userDatabase.clear()
        userDatabase["test@gmail.com"] = "123456"
        userDatabase["test2@gmail.com"] = "123456"
        userKeyCloud.clear()
    }
}

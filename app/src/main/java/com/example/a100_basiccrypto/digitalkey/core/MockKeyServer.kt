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
 * Enhanced Metadata stored on the cloud for each key.
 */
data class CloudKeyRecord(
    val keyId: String,               // Local ID
    val moduleID: String,            // Vehicle Hardware ID (Hex)
    val devicePublicKey: String,     // Phone's Dilithium PK (Hex)
    val vehiclePublicKey: String,    // Vehicle's Dilithium PK (Hex)
    val role: Role,                  // OWNER / FRIEND
    val permissions: Int,            // Bitmask
    val keyState: KeyState,          // ACTIVE, REVOKED, etc.
    val validityStart: Long,
    val validityEnd: Long,
    val usageLimit: Int,
    val friendlyName: String,
    val metadata: CarMetadata        // Brand, Plate, Color, etc.
)

/**
 * Mock Server to simulate User Authentication, Key Sharing, and Cloud Sync.
 */
object MockKeyServer {
    private const val TAG = "MockKeyServer"

    // --- AUTH STORAGE ---
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
        Log.d(TAG, "☁️ [SERVER] Registering user: $email")
        delay(800)
        if (userDatabase.containsKey(email)) {
            Log.e(TAG, "❌ [SERVER] Registration failed: Email $email already exists.")
            return false
        }
        userDatabase[email] = pass
        Log.i(TAG, "✅ [SERVER] User registered successfully: $email")
        return true
    }

    suspend fun login(email: String, pass: String): AuthManager.UserProfile? {
        Log.d(TAG, "☁️ [SERVER] Login attempt for user: $email")
        delay(1000)
        if (userDatabase[email] == pass) {
            val profile = AuthManager.UserProfile(
                email = email,
                displayName = email.substringBefore("@").replaceFirstChar { it.uppercase() },
                token = "mock_jwt_" + UUID.randomUUID().toString().take(8)
            )
            Log.i(TAG, "✅ [SERVER] Login success: ${profile.displayName} (Token: ${profile.token})")
            return profile
        }
        Log.e(TAG, "❌ [SERVER] Login failed: Invalid credentials for $email")
        return null
    }

    /**
     * Synchronizes a full key record to the user's cloud account.
     */
    suspend fun syncKeyToCloud(token: String, record: CloudKeyRecord): Boolean {
        Log.d(TAG, "☁️ [SERVER] Syncing Key [${record.keyId}] for vehicle [${record.metadata.modelName}]...")
        delay(1200)
        
        val keys = userKeyCloud.getOrPut(token) { mutableListOf() }
        keys.removeAll { it.keyId == record.keyId || it.moduleID == record.moduleID }
        keys.add(record)
        
        Log.i(TAG, "✅ [SERVER] Cloud Sync Complete. User [Token: $token] now owns ${keys.size} key(s).")
        Log.d(TAG, "   └─ ModuleID: ${record.moduleID}, Role: ${record.role}, Permissions: ${record.permissions}")
        return true
    }

    suspend fun fetchUserKeys(token: String): List<CloudKeyRecord> {
        Log.d(TAG, "☁️ [SERVER] Fetching keys for token: $token")
        delay(1000)
        val keys = userKeyCloud[token] ?: emptyList()
        Log.i(TAG, "✅ [SERVER] Found ${keys.size} key(s) for this account.")
        return keys
    }

    // --- SHARING METHODS ---

    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "☁️ [SERVER] Receiving Invitation from Owner for Recipient: ${invitation.recipient}")
        delay(1000)
        pendingInvitation = invitation
        _invitationFlow.emit(invitation)
        Log.i(TAG, "✅ [SERVER] Invitation uploaded and broadcasted. Waiting for friend to claim...")
        return true
    }

    suspend fun downloadInvitation(): ShareInvitation? {
        Log.d(TAG, "☁️ [SERVER] Friend is checking for pending invitations...")
        delay(500)
        val inv = pendingInvitation
        if (inv != null) {
            Log.i(TAG, "✅ [SERVER] Found invitation for vehicle: ${inv.friendlyName}")
        } else {
            Log.w(TAG, "ℹ️ [SERVER] No pending invitations found.")
        }
        return inv
    }

    suspend fun notifyActivation(ap: ByteArray) {
        Log.d(TAG, "☁️ [SERVER] Key Activated by Friend. Notifying Owner...")
        delay(500)
        _activationFlow.emit(ap)
        Log.i(TAG, "✅ [SERVER] Owner notified of successful activation.")
    }

    fun reset() {
        Log.w(TAG, "⚠️ [SERVER] Hard Resetting Mock Server Data...")
        pendingInvitation = null
        userDatabase.clear()
        userDatabase["test@gmail.com"] = "123456"
        userDatabase["test2@gmail.com"] = "123456"
        userKeyCloud.clear()
    }
}

package com.example.a100_basiccrypto.data.api.mock

import android.util.Log
import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.api.UserProfileResponse
import com.example.a100_basiccrypto.data.model.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.UUID

/**
 * Mock Server Implementation of KeyServerApi.
 */
object MockKeyServer : KeyServerApi {
    private const val TAG = "MockKeyServer"

    private val userDatabase = mutableMapOf<String, CloudUserProfile>().apply {
        put("test@gmail.com", CloudUserProfile("test@gmail.com", "Owner User", "123456"))
        put("test2@gmail.com", CloudUserProfile("test2@gmail.com", "Friend User", "123456"))
    }
    
    private val userKeyCloud = mutableMapOf<String, MutableList<CloudKeyRecord>>()
    private val invitationInbox = mutableMapOf<String, MutableList<ShareInvitation>>()
    private val onlineUsers = mutableSetOf<String>()
    
    private val _invitationFlow = MutableSharedFlow<ShareInvitation>(replay = 0)
    override val invitationFlow = _invitationFlow.asSharedFlow()
    
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    override val activationFlow = _activationFlow.asSharedFlow()

    private val _statusUpdateFlow = MutableSharedFlow<InvitationStatusUpdate>(replay = 0)
    override val statusUpdateFlow = _statusUpdateFlow.asSharedFlow()

    override fun setOnline(email: String) {
        onlineUsers.add(email)
        Log.i(TAG, "📱 [SERVER] User $email is now ONLINE")
    }

    override fun setOffline(email: String) {
        onlineUsers.remove(email)
        Log.i(TAG, "📱 [SERVER] User $email is now OFFLINE")
    }

    override suspend fun login(email: String, pass: String): UserProfileResponse? {
        delay(1000)
        val user = userDatabase[email]
        if (user != null && user.password == pass) {
            setOnline(email)
            Log.d(TAG, "🔑 [AUTH] User $email logged in successfully.")
            return UserProfileResponse(
                email = email,
                displayName = user.displayName,
                token = "mock_jwt_" + UUID.randomUUID().toString().take(8)
            )
        }
        Log.w(TAG, "❌ [AUTH] Login failed for user: $email")
        return null
    }

    override suspend fun register(email: String, pass: String, displayName: String): Boolean {
        delay(800)
        if (userDatabase.containsKey(email)) return false
        val name = if (displayName.isNotEmpty()) displayName else email.substringBefore("@")
        userDatabase[email] = CloudUserProfile(email, name, pass)
        Log.i(TAG, "👤 [AUTH] New user registered: $email")
        return true
    }

    override suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String? {
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
            val invParentId = inv.ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            invParentId.equals(parentKeyIdHex, ignoreCase = true)
        }) {
            Log.w(TAG, "🚫 [LEGALITY] DENIED: Car $parentKeyIdHex already has a pending invitation for $recipientEmail.")
            return "An invitation for this vehicle is already pending for this recipient."
        }
        
        Log.i(TAG, "✅ [LEGALITY] PASSED for $recipientEmail")
        return null
    }

    override suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "☁️ [UPLOAD] Processing Invitation from ${invitation.senderEmail} to ${invitation.recipientEmail}")
        delay(1000)

        val ap = invitation.ap
        if (invitation.carMetadata == null && ap.size >= 9) {
            val parentKeyIdHex = ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }.uppercase()
            
            val foundMetadata = userKeyCloud.values.flatten()
                .find { it.keyId.equals(parentKeyIdHex, ignoreCase = true) }?.metadata
            
            if (foundMetadata != null) {
                invitation.carMetadata = foundMetadata
                Log.d(TAG, "📦 [UPLOAD] Attached car metadata to invitation: ${foundMetadata.modelName} (Plate: ${foundMetadata.licensePlate})")
            } else {
                Log.w(TAG, "⚠️ [UPLOAD] Metadata NOT found for Parent KeyID: $parentKeyIdHex. Checking fallback...")
                val fallbackMetadata = userKeyCloud.values.flatten()
                    .find { it.keyId.startsWith(parentKeyIdHex, ignoreCase = true) }?.metadata
                if (fallbackMetadata != null) {
                    invitation.carMetadata = fallbackMetadata
                    Log.d(TAG, "📦 [UPLOAD] Attached car metadata via prefix fallback: ${fallbackMetadata.licensePlate}")
                } else {
                    Log.w(TAG, "❌ [UPLOAD] Metadata truly NOT found for Parent KeyID: $parentKeyIdHex. Friend will see 'N/A'.")
                }
            }
        }

        val inbox = invitationInbox.getOrPut(invitation.recipientEmail) { mutableListOf() }
        inbox.add(invitation)
        Log.i(TAG, "📩 [INBOX] Invitation stored in ${invitation.recipientEmail}'s inbox. Total pending: ${inbox.size}")

        if (onlineUsers.contains(invitation.recipientEmail)) {
            Log.i(TAG, "🚀 [PUSH] Recipient ${invitation.recipientEmail} is ONLINE. Emitting real-time invitation.")
            _invitationFlow.emit(invitation)
        } else {
            Log.d(TAG, "💤 [PUSH] Recipient ${invitation.recipientEmail} is OFFLINE. Invitation stays in Inbox.")
        }
        return true
    }

    override suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray?) {
        Log.i(TAG, "🛡️ [SERVER] Owner $senderEmail is revoking key for $recipientEmail. Signed: ${signature != null}")
        delay(500)
        
        val removedFromInbox = invitationInbox[recipientEmail]?.removeAll { it.ap.contentEquals(ap) } ?: false
        if (removedFromInbox) {
            Log.d(TAG, "🗑️ [INBOX] Removed invitation from $recipientEmail's inbox.")
        }

        if (ap.size >= 9) {
            val parentKeyIdHex = ap.sliceArray(1 until 9).joinToString("") { "%02x".format(it) }
            userKeyCloud[recipientEmail]?.removeAll { it.parentKeyId.equals(parentKeyIdHex, ignoreCase = true) || it.ownerEmail.equals(senderEmail, ignoreCase = true) }
            userKeyCloud[senderEmail]?.removeAll { it.holderEmail.equals(recipientEmail, ignoreCase = true) && it.parentKeyId.equals(parentKeyIdHex, ignoreCase = true) }
            Log.d(TAG, "☁️ [SYNC] Revoked key records for $parentKeyIdHex removed from Cloud storage.")
        }

        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, InvitationStatus.REVOKED, recipientEmail))
    }

    override suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean {
        Log.i(TAG, "🚨 [SERVER] Owner $ownerEmail requested full Revoke/Reset for Module: $moduleID")
        delay(1000)

        val allRecords = userKeyCloud.values.flatten()
        val affectedKeys = allRecords.filter { it.moduleID.equals(moduleID, ignoreCase = true) }
        
        if (affectedKeys.isEmpty()) {
            Log.w(TAG, "⚠️ [SERVER] No keys found for Module $moduleID on Cloud.")
            return true
        }

        userKeyCloud.values.forEach { list ->
            list.removeAll { it.moduleID.equals(moduleID, ignoreCase = true) }
        }

        invitationInbox.values.forEach { list ->
            list.removeAll { it.moduleID?.joinToString("") { b -> "%02x".format(b) }.equals(moduleID, ignoreCase = true) }
        }

        Log.i(TAG, "✅ [SERVER] Full Cloud Wipe complete for Module: $moduleID")
        return true
    }

    override suspend fun reportInvitationOutcome(recipientEmail: String, ap: ByteArray, status: InvitationStatus, senderEmail: String) {
        Log.i(TAG, "📣 [OUTCOME] User $recipientEmail reported: $status. Notifying Owner: $senderEmail")
        
        val removed = invitationInbox[recipientEmail]?.removeAll { it.ap.contentEquals(ap) } ?: false
        if (removed) {
            Log.d(TAG, "🗑️ [INBOX] Cleaned up AP from $recipientEmail's inbox.")
        }

        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, status, recipientEmail))
    }

    override suspend fun fetchPendingInvitations(email: String): List<ShareInvitation> {
        delay(800)
        return invitationInbox[email] ?: emptyList()
    }

    override fun removeInvitation(email: String, ap: ByteArray) {
        val inbox = invitationInbox[email] ?: return
        inbox.removeAll { it.ap.contentEquals(ap) }
    }

    override suspend fun notifyActivation(ap: ByteArray) {
        _activationFlow.emit(ap)
    }

    override suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        val keys = userKeyCloud.getOrPut(email) { mutableListOf() }
        keys.removeAll { it.keyId.equals(record.keyId, ignoreCase = true) || it.moduleID.equals(record.moduleID, ignoreCase = true) }
        keys.add(record)
        return true
    }

    override suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return userKeyCloud[email] ?: emptyList()
    }

    fun reset() {
        onlineUsers.clear()
        userKeyCloud.clear()
        invitationInbox.clear()
    }
}

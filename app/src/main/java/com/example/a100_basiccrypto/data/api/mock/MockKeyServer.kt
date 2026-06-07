package com.example.a100_basiccrypto.data.api.mock

import android.util.Log
import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.model.*
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.hexToBytes
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.UUID

/**
 * Enhanced Mock Server simulating advanced Auth and Sharing flows.
 */
object MockKeyServer : KeyServerApi {
    private const val TAG = "MockKeyServer"
    private const val MOCK_CLOUD_PK = "MOCK_CLOUD_DILITHIUM_PK_HEX_123456"

    private val userDatabase = mutableMapOf<String, String>().apply {
        put("user01@gmail.com", "123456")
        put("test@gmail.com", "123456")
        put("friend@gmail.com", "123456")
    }
    
    // email -> identity_pk
    private val deviceDatabase = mutableMapOf<String, String>()
    
    private val userKeyCloud = mutableMapOf<String, MutableList<CloudKeyRecord>>()
    private val invitationInbox = mutableMapOf<String, MutableList<InvitationDetail>>()
    private val onlineUsers = mutableSetOf<String>()

    private val revokeJobs = mutableListOf<RevokeJob>()

    private val _invitationFlow = MutableSharedFlow<InvitationDetail>(replay = 0)
    override val invitationFlow = _invitationFlow.asSharedFlow()
    
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    override val activationFlow = _activationFlow.asSharedFlow()

    private val _statusUpdateFlow = MutableSharedFlow<InvitationStatusUpdate>(replay = 0)
    override val statusUpdateFlow = _statusUpdateFlow.asSharedFlow()

    private var currentSessionEmail: String? = null

    override fun setOnline(email: String) {
        onlineUsers.add(email)
        currentSessionEmail = email
    }

    override fun setOffline(email: String) {
        onlineUsers.remove(email)
        if (currentSessionEmail == email) currentSessionEmail = null
    }

    // --- AUTH APIs ---

    override suspend fun login(request: LoginRequest): AuthResponse? {
        delay(500)
        val storedPass = userDatabase[request.email]
        if (storedPass == request.password) {
            val boundPk = deviceDatabase[request.email]
            if (boundPk != null && boundPk != request.identity_pk) return null
            if (boundPk == null) deviceDatabase[request.email] = request.identity_pk

            setOnline(request.email)
            return AuthResponse(
                message = "Đăng nhập thành công",
                accessToken = "mock_access_token_" + UUID.randomUUID().toString().take(6),
                refreshToken = "mock_refresh_token_" + UUID.randomUUID().toString().take(8),
                user = UserResponse(UUID.randomUUID().toString(), request.email, request.displayName ?: "User", "USER"),
                device = DeviceResponse("did", request.identity_pk, request.deviceName ?: "Unknown", request.fcmToken, null),
                cloudPublicKey = MOCK_CLOUD_PK
            )
        }
        return null
    }

    override suspend fun refresh(request: RefreshRequest): AuthResponse? {
        return AuthResponse("Cấp lại thành công", "new_access_token", null, UserResponse("u", "user@mail.com", "User", "USER"), null, MOCK_CLOUD_PK)
    }

    override suspend fun getMe(token: String): MeResponse? {
        return MeResponse(UserResponse("u", "user@mail.com", "User", "USER"), emptyList(), MOCK_CLOUD_PK)
    }

    override suspend fun register(email: String, pass: String, displayName: String): Boolean {
        userDatabase[email] = pass
        return true
    }

    // --- SHARING APIs (REST Standard) ---

    override suspend fun checkLegality(request: ShareCheckRequest): ShareCheckResponse? {
        delay(300)
        val exists = userDatabase.containsKey(request.recipientEmail)
        return if (exists) {
            ShareCheckResponse(true, "Có thể chia sẻ", request.parentKeyId, "mock_mid_123", RecipientInfo("uid", request.recipientEmail, "Friend Name"))
        } else {
            ShareCheckResponse(false, "Recipient does not exist", null, null, null)
        }
    }

    override suspend fun invite(request: ShareInviteRequest): ShareInviteResponse? {
        delay(500)
        val invitation = InvitationDetail(
            id = UUID.randomUUID().toString(),
            senderId = "owner_id",
            recipientEmail = request.recipientEmail,
            moduleID = request.moduleID,
            parentKeyId = request.parentKeyId,
            ap_blob = request.ap_blob,
            pin_hash = request.pin_hash,
            status = "PENDING",
            car_metadata = request.car_metadata,
            senderEmail = "owner@mail.com",
            senderName = "Owner"
        )
        
        val inbox = invitationInbox.getOrPut(request.recipientEmail) { mutableListOf() }
        inbox.add(invitation)
        
        if (onlineUsers.contains(request.recipientEmail)) {
            _invitationFlow.emit(invitation)
        }
        
        return ShareInviteResponse("Invite success", invitation)
    }

    override suspend fun fetchPendingInvitations(email: String): List<InvitationDetail> {
        return invitationInbox[email] ?: emptyList()
    }

    override suspend fun claimInvitation(request: ShareClaimRequest): InvitationDetail? {
        delay(300)
        // Find and mark as CLAIMED in mock DB
        for (inbox in invitationInbox.values) {
            val found = inbox.find { it.id == request.invitationId }
            if (found != null) return found
        }
        return null
    }

    override suspend fun reportOutcome(report: ShareOutcomeReport): Boolean {
        Log.i(TAG, "📈 [REPORT] Outcome for ${report.invitationId}: ${report.status}")
        
        if (report.status == "CLAIMED") {
            // Find and mark as CLAIMED/ACTIVE in mock DB
            for (inbox in invitationInbox.values) {
                val found = inbox.find { it.id == report.invitationId }
                if (found != null) {
                    // Update key in cloud storage
                    val cloudRecord = CloudKeyRecord(
                        keyId = report.keyId ?: UUID.randomUUID().toString(),
                        moduleID = found.moduleID ?: "mock_mid",
                        ownerEmail = found.senderEmail ?: "owner@mail.com",
                        holderEmail = found.recipientEmail ?: "friend@mail.com",
                        holderNickname = report.holderNickname ?: "",
                        parentKeyId = found.parentKeyId,
                        devicePublicKey = report.devicePublicKey ?: "",
                        vehiclePublicKey = report.vehiclePublicKey ?: "",
                        role = Role.FRIEND,
                        permissions = report.permissions ?: 0,
                        keyState = KeyState.ACTIVE,
                        validityStart = report.validityStart ?: 0,
                        validityEnd = report.validityEnd ?: 0,
                        usageLimit = report.usageLimit ?: 0,
                        friendlyName = found.car_metadata?.modelName ?: "Shared Vehicle",
                        metadata = found.car_metadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata()
                    )
                    
                    val keys = userKeyCloud.getOrPut(cloudRecord.holderEmail) { mutableListOf() }
                    keys.add(cloudRecord)
                    
                    // Also notify owner via statusUpdateFlow
                    _statusUpdateFlow.emit(InvitationStatusUpdate(
                        found.ap_blob?.let { it.hexToBytes() } ?: byteArrayOf(),
                        InvitationStatus.CLAIMED,
                        found.recipientEmail ?: ""
                    ))
                    
                    inbox.remove(found)
                    return true
                }
            }
        }
        return true
    }

    // --- NEW REVOKE APIs ---

    override suspend fun revokeFriend(request: RevokeFriendRequest): RevokeFriendResponse? {
        delay(500)
        val jobId = UUID.randomUUID().toString()
        val job = RevokeJob(
            id = jobId,
            keyId = request.keyId ?: "FRIEND_KEY_123",
            moduleId = request.moduleID,
            requesterEmail = "owner@mail.com",
            requesterName = "Owner",
            targetEmail = request.friendEmail ?: "friend@mail.com",
            targetName = "Friend",
            status = "PENDING",
            reason = request.reason
        )
        revokeJobs.add(job)

        return RevokeFriendResponse(
            success = true,
            message = "Friend key is REVOKED on Cloud. Job created.",
            flow = "OWNER_REVOKE_FRIEND",
            state = "REVOKED",
            revokeJob = job,
            vehicleCommand = VehicleCommand(
                command = "INS_REMOVE_FRIEND",
                transport = "BLE_FAST_ACTION",
                payload = mapOf("moduleID" to request.moduleID, "keyId" to (request.keyId ?: ""))
            ),
            friendSoftWipe = FriendSoftWipe(null, request.friendEmail, request.keyId, request.moduleID),
            friendKey = null
        )
    }

    override suspend fun fetchRevokeJobs(): List<RevokeJob> {
        delay(300)
        return revokeJobs.filter { it.status == "PENDING" }
    }

    override suspend fun reportRevokeJob(report: RevokeJobReport): Boolean {
        delay(200)
        val index = revokeJobs.indexOfFirst { it.id == report.jobId }
        if (index != -1) {
            revokeJobs[index] = revokeJobs[index].copy(status = "REVOKED")
            Log.i(TAG, "🏁 [JOB-REPORT] Job ${report.jobId} finalized as ${report.status}")
            return true
        }
        return false
    }

    // --- NEW SYNC APIs ---

    override suspend fun uploadKey(request: SyncKeyRequest): SyncKeyResponse? {
        delay(500)
        Log.i(TAG, "☁️ [SYNC-UPLOAD] Uploading key ${request.keyId} for module ${request.moduleID}")
        
        val email = currentSessionEmail ?: "owner@mail.com"
        
        val detail = SyncKeyDetail(
            keyId = request.keyId,
            moduleID = request.moduleID,
            ownerId = UUID.randomUUID().toString(),
            holderId = UUID.randomUUID().toString(),
            parentKeyId = request.parentKeyId,
            role = request.role,
            keyState = if (request.keyState == "CLAIMED") "ACTIVE" else request.keyState,
            permissions = request.permissions,
            friendlyName = request.friendlyName,
            devicePublicKey = request.devicePublicKey,
            vehiclePublicKey = request.vehiclePublicKey,
            validityStart = request.validityStart,
            validityEnd = request.validityEnd,
            usageLimit = request.usageLimit,
            metadata = request.metadata
        )
        
        // Update mock cloud storage
        val cloudRecord = CloudKeyRecord(
            keyId = detail.keyId,
            moduleID = detail.moduleID,
            ownerEmail = if (detail.role == "OWNER") email else "owner@mail.com",
            holderEmail = email,
            holderNickname = request.holderNickname ?: "",
            parentKeyId = detail.parentKeyId,
            devicePublicKey = detail.devicePublicKey,
            vehiclePublicKey = detail.vehiclePublicKey,
            role = Role.valueOf(detail.role),
            permissions = detail.permissions,
            keyState = KeyState.valueOf(detail.keyState),
            validityStart = detail.validityStart,
            validityEnd = detail.validityEnd,
            usageLimit = detail.usageLimit,
            friendlyName = detail.friendlyName ?: "Shared Vehicle",
            metadata = detail.metadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata()
        )
        
        val keys = userKeyCloud.getOrPut(email) { mutableListOf() }
        keys.removeAll { it.keyId == cloudRecord.keyId }
        keys.add(cloudRecord)
        
        return SyncKeyResponse("Sync key thành công", detail)
    }

    override suspend fun fetchKeysList(): List<SyncKeyDetail> {
        delay(300)
        val email = currentSessionEmail ?: "owner@mail.com"
        val cloudKeys = userKeyCloud[email] ?: emptyList()
        return cloudKeys.map { 
            SyncKeyDetail(
                keyId = it.keyId,
                moduleID = it.moduleID,
                ownerId = "oid",
                holderId = "hid",
                parentKeyId = it.parentKeyId,
                role = it.role.name,
                keyState = it.keyState.name,
                permissions = it.permissions,
                friendlyName = it.friendlyName ?: "My Vehicle",
                devicePublicKey = it.devicePublicKey,
                vehiclePublicKey = it.vehiclePublicKey,
                validityStart = it.validityStart,
                validityEnd = it.validityEnd,
                usageLimit = it.usageLimit,
                metadata = it.metadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata()
            )
        }
    }

    // --- LEGACY / HELPER METHODS ---

    override suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray?) {
        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, InvitationStatus.REVOKED, recipientEmail))
    }

    override suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean {
        userKeyCloud.values.forEach { it.removeAll { k -> k.moduleID == moduleID } }
        return true
    }

    override fun removeInvitation(email: String, ap: ByteArray) {
        val apHex = ap.toHex()
        invitationInbox[email]?.removeAll { (it.ap_blob ?: "") == apHex }
    }

    override suspend fun notifyActivation(ap: ByteArray) {
        _activationFlow.emit(ap)
    }

    override suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        val keys = userKeyCloud.getOrPut(email) { mutableListOf() }
        keys.removeAll { it.keyId == record.keyId }
        keys.add(record)
        return true
    }

    override suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return userKeyCloud[email] ?: emptyList()
    }
}

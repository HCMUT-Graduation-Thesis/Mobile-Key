package com.example.a100_basiccrypto.data.api.mock

import android.util.Log
import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.model.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.UUID

/**
 * Enhanced Mock Server simulating advanced Auth flows and device binding.
 */
object MockKeyServer : KeyServerApi {
    private const val TAG = "MockKeyServer"
    private const val MOCK_CLOUD_PK = "MOCK_CLOUD_DILITHIUM_PK_HEX_123456"

    private val userDatabase = mutableMapOf<String, String>().apply {
        put("user01@gmail.com", "123456")
        put("test@gmail.com", "123456")
    }
    
    // email -> identity_pk
    private val deviceDatabase = mutableMapOf<String, String>()
    
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

    override suspend fun login(request: LoginRequest): AuthResponse? {
        delay(1000)
        val storedPass = userDatabase[request.email]
        if (storedPass != null && storedPass == request.password) {
            
            // Simulating Device Binding Check
            val boundPk = deviceDatabase[request.email]
            if (boundPk != null && boundPk != request.identity_pk) {
                Log.e(TAG, "❌ [AUTH] Device mismatch for ${request.email}")
                return null
            }
            if (boundPk == null) {
                deviceDatabase[request.email] = request.identity_pk
                Log.i(TAG, "🔗 [SERVER] New device bound for ${request.email}")
            }

            setOnline(request.email)
            Log.d(TAG, "🔑 [AUTH] Login Success: ${request.email}")

            return AuthResponse(
                message = "Đăng nhập thành công",
                accessToken = "mock_access_token_" + UUID.randomUUID().toString().take(6),
                refreshToken = "mock_refresh_token_" + UUID.randomUUID().toString().take(8),
                user = UserResponse(UUID.randomUUID().toString(), request.email, request.displayName ?: "User", "USER"),
                device = DeviceResponse(UUID.randomUUID().toString(), request.identity_pk, request.deviceName ?: "Unknown", request.fcmToken, "2026-06-06T12:00:00Z"),
                cloudPublicKey = MOCK_CLOUD_PK
            )
        }
        return null
    }

    override suspend fun refresh(request: RefreshRequest): AuthResponse? {
        delay(500)
        if (request.refreshToken.startsWith("mock_refresh_token_")) {
            return AuthResponse(
                message = "Cấp lại access token thành công",
                accessToken = "mock_access_token_new_" + UUID.randomUUID().toString().take(6),
                user = UserResponse("uid", "user@example.com", "User", "USER"),
                cloudPublicKey = MOCK_CLOUD_PK
            )
        }
        return null
    }

    override suspend fun getMe(token: String): MeResponse? {
        delay(500)
        if (token.startsWith("mock_access_token_")) {
            return MeResponse(
                user = UserResponse("uid", "user@example.com", "User", "USER"),
                devices = listOf(DeviceResponse("did", "identity_pk", "Phone", "fcm", "now")),
                cloudPublicKey = MOCK_CLOUD_PK
            )
        }
        return null
    }

    override suspend fun register(email: String, pass: String, displayName: String): Boolean {
        delay(800)
        if (userDatabase.containsKey(email)) return false
        userDatabase[email] = pass
        return true
    }

    // --- SHARING & OTHER METHODS (RESTORED FULL LOGIC) ---

    override suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String? {
        delay(500)
        if (!userDatabase.containsKey(recipientEmail)) return "Recipient account does not exist."
        return null
    }

    override suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        delay(1000)
        val inbox = invitationInbox.getOrPut(invitation.recipientEmail) { mutableListOf() }
        inbox.add(invitation)
        if (onlineUsers.contains(invitation.recipientEmail)) _invitationFlow.emit(invitation)
        return true
    }

    override suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray?) {
        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, InvitationStatus.REVOKED, recipientEmail))
    }

    override suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean {
        userKeyCloud.values.forEach { it.removeAll { k -> k.moduleID == moduleID } }
        return true
    }

    override suspend fun reportInvitationOutcome(recipientEmail: String, ap: ByteArray, status: InvitationStatus, senderEmail: String) {
        _statusUpdateFlow.emit(InvitationStatusUpdate(ap, status, recipientEmail))
    }

    override suspend fun fetchPendingInvitations(email: String): List<ShareInvitation> {
        return invitationInbox[email] ?: emptyList()
    }

    override fun removeInvitation(email: String, ap: ByteArray) {
        invitationInbox[email]?.removeAll { it.ap.contentEquals(ap) }
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

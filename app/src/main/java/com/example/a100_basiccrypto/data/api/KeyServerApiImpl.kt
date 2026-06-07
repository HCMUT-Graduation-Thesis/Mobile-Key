package com.example.a100_basiccrypto.data.api

import android.util.Log
import com.example.a100_basiccrypto.data.model.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

class KeyServerApiImpl(private val api: RetrofitKeyServerApi) : KeyServerApi {

    companion object {
        private const val TAG = "KeyServerApiImpl"
    }

    private val _invitationFlow = MutableSharedFlow<InvitationDetail>(replay = 0)
    override val invitationFlow: SharedFlow<InvitationDetail> = _invitationFlow.asSharedFlow()

    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    override val activationFlow: SharedFlow<ByteArray> = _activationFlow.asSharedFlow()

    private val _statusUpdateFlow = MutableSharedFlow<InvitationStatusUpdate>(replay = 0)
    override val statusUpdateFlow: SharedFlow<InvitationStatusUpdate> = _statusUpdateFlow.asSharedFlow()

    override fun setOnline(email: String) {}
    override fun setOffline(email: String) {}

    // --- Auth APIs ---

    override suspend fun login(request: LoginRequest): AuthResponse? {
        val response = api.login(request)
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun refresh(request: RefreshRequest): AuthResponse? {
        val response = api.refresh(request)
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun getMe(token: String): MeResponse? {
        val response = api.getMe("Bearer $token")
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun register(email: String, pass: String, displayName: String): Boolean {
        // Not yet implemented in Retrofit interface, but can be added
        return false
    }

    // --- Sharing APIs ---

    override suspend fun checkLegality(request: ShareCheckRequest): ShareCheckResponse? {
        val response = api.checkLegality(request)
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun invite(request: ShareInviteRequest): ShareInviteResponse? {
        val response = api.invite(request)
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun fetchPendingInvitations(email: String): List<InvitationDetail> {
        val response = api.fetchPendingInvitations()
        return if (response.isSuccessful) response.body() ?: emptyList() else emptyList()
    }

    override suspend fun claimInvitation(request: ShareClaimRequest): InvitationDetail? {
        val response = api.claimInvitation(request)
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun reportOutcome(report: ShareOutcomeReport): Boolean {
        val response = api.reportOutcome(report)
        return response.isSuccessful && response.body() == true
    }

    // --- Revocation APIs ---

    override suspend fun revokeFriend(request: RevokeFriendRequest): RevokeFriendResponse? {
        val response = api.revokeFriend(request)
        return if (response.isSuccessful) response.body() else null
    }

    override suspend fun fetchRevokeJobs(): List<RevokeJob> {
        val response = api.fetchRevokeJobs()
        return if (response.isSuccessful) response.body()?.jobs ?: emptyList() else emptyList()
    }

    override suspend fun reportRevokeJob(report: RevokeJobReport): Boolean {
        val response = api.reportRevokeJob(report)
        return response.isSuccessful && response.body() == true
    }

    // --- Sync APIs ---

    override suspend fun uploadKey(request: SyncKeyRequest): SyncKeyResponse? {
        return try {
            Log.d(TAG, "📡 [API-SYNC] Uploading key: ${request.keyId}")
            val response = api.uploadKey(request)
            if (response.isSuccessful) {
                Log.i(TAG, "✅ [API-SYNC] Key uploaded successfully.")
                response.body()
            } else {
                Log.e(TAG, "❌ [API-SYNC] Upload failed: ${response.code()} ${response.message()}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ [API-SYNC] Network error: ${e.message}")
            null
        }
    }

    override suspend fun fetchKeysList(): List<SyncKeyDetail> {
        return try {
            Log.d(TAG, "📡 [API-SYNC] Fetching keys list...")
            val response = api.fetchKeysList()
            if (response.isSuccessful) {
                val list = response.body() ?: emptyList()
                Log.i(TAG, "✅ [API-SYNC] Fetched ${list.size} keys.")
                list
            } else {
                Log.e(TAG, "❌ [API-SYNC] Fetch failed: ${response.code()}")
                emptyList()
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ [API-SYNC] Network error: ${e.message}")
            emptyList()
        }
    }

    // --- Management APIs (Legacy / Helper) ---

    override suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray?) {
        // Legacy, usually handled by revokeFriend now
    }

    override suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean {
        return false
    }

    override fun removeInvitation(email: String, ap: ByteArray) {}

    override suspend fun notifyActivation(ap: ByteArray) {}

    override suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        return false
    }

    override suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return emptyList()
    }
}

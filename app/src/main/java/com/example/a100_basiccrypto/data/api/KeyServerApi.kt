package com.example.a100_basiccrypto.data.api

import com.example.a100_basiccrypto.data.model.*
import kotlinx.coroutines.flow.SharedFlow

interface KeyServerApi {
    val invitationFlow: SharedFlow<InvitationDetail>
    val activationFlow: SharedFlow<ByteArray>
    val statusUpdateFlow: SharedFlow<InvitationStatusUpdate>

    fun setOnline(email: String)
    fun setOffline(email: String)
    
    // Auth APIs
    suspend fun login(request: LoginRequest): AuthResponse?
    suspend fun refresh(request: RefreshRequest): AuthResponse?
    suspend fun getMe(token: String): MeResponse?
    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean
    
    // Sharing APIs (Updated to Cloud Standard)
    suspend fun checkLegality(request: ShareCheckRequest): ShareCheckResponse?
    suspend fun invite(request: ShareInviteRequest): ShareInviteResponse?
    suspend fun fetchPendingInvitations(email: String): List<InvitationDetail>
    suspend fun claimInvitation(request: ShareClaimRequest): InvitationDetail?
    suspend fun reportOutcome(report: ShareOutcomeReport): Boolean
    
    // Management APIs
    suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray? = null)
    suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean
    fun removeInvitation(email: String, ap: ByteArray)
    suspend fun notifyActivation(ap: ByteArray)
    
    suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean
    suspend fun fetchUserKeys(email: String): List<CloudKeyRecord>
}

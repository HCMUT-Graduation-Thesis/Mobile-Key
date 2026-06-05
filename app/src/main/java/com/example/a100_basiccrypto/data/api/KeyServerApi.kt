package com.example.a100_basiccrypto.data.api

import com.example.a100_basiccrypto.data.model.*
import kotlinx.coroutines.flow.SharedFlow

interface KeyServerApi {
    val invitationFlow: SharedFlow<ShareInvitation>
    val activationFlow: SharedFlow<ByteArray>
    val statusUpdateFlow: SharedFlow<InvitationStatusUpdate>

    fun setOnline(email: String)
    fun setOffline(email: String)
    
    suspend fun login(email: String, pass: String): UserProfileResponse?
    suspend fun register(email: String, pass: String, displayName: String = ""): Boolean
    
    suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String?
    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean
    suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray? = null)
    suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean
    suspend fun reportInvitationOutcome(recipientEmail: String, ap: ByteArray, status: InvitationStatus, senderEmail: String)
    suspend fun fetchPendingInvitations(email: String): List<ShareInvitation>
    fun removeInvitation(email: String, ap: ByteArray)
    suspend fun notifyActivation(ap: ByteArray)
    
    suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean
    suspend fun fetchUserKeys(email: String): List<CloudKeyRecord>
}

data class UserProfileResponse(
    val email: String,
    val displayName: String,
    val token: String
)

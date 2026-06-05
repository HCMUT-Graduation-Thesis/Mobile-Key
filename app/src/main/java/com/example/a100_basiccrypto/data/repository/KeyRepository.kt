package com.example.a100_basiccrypto.data.repository

import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.model.*
import kotlinx.coroutines.flow.SharedFlow

class KeyRepository(private val api: KeyServerApi) {
    val invitationFlow: SharedFlow<ShareInvitation> = api.invitationFlow
    val activationFlow: SharedFlow<ByteArray> = api.activationFlow
    val statusUpdateFlow: SharedFlow<InvitationStatusUpdate> = api.statusUpdateFlow

    suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String? {
        return api.checkInvitationLegality(senderEmail, recipientEmail, parentKeyIdHex)
    }

    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        return api.uploadInvitation(invitation)
    }

    suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray? = null) {
        api.revokeInvitation(senderEmail, recipientEmail, ap, signature)
    }

    suspend fun revokeOwner(ownerEmail: String, moduleID: String): Boolean {
        return api.revokeOwner(ownerEmail, moduleID)
    }

    suspend fun reportInvitationOutcome(recipientEmail: String, ap: ByteArray, status: InvitationStatus, senderEmail: String) {
        api.reportInvitationOutcome(recipientEmail, ap, status, senderEmail)
    }

    suspend fun fetchPendingInvitations(email: String): List<ShareInvitation> {
        return api.fetchPendingInvitations(email)
    }

    fun removeInvitation(email: String, ap: ByteArray) {
        api.removeInvitation(email, ap)
    }

    suspend fun notifyActivation(ap: ByteArray) {
        api.notifyActivation(ap)
    }

    suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        return api.syncKeyToCloud(email, record)
    }

    suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return api.fetchUserKeys(email)
    }
}

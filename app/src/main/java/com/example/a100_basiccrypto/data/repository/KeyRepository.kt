package com.example.a100_basiccrypto.data.repository

import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.model.*
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.hexToBytes

class KeyRepository(private val api: KeyServerApi) {

    val invitationFlow = api.invitationFlow
    val activationFlow = api.activationFlow
    val statusUpdateFlow = api.statusUpdateFlow

    // --- NEW Sharing APIs (REST Standard) ---

    suspend fun checkSharingLegality(recipientEmail: String, parentKeyId: String): ShareCheckResponse? {
        val request = ShareCheckRequest(recipientEmail, parentKeyId)
        return api.checkLegality(request)
    }

    suspend fun sendInvitation(request: ShareInviteRequest): ShareInviteResponse? {
        return api.invite(request)
    }

    suspend fun fetchPendingInvitations(email: String): List<InvitationDetail> {
        return api.fetchPendingInvitations(email)
    }

    suspend fun claimInvitation(invitationId: String): InvitationDetail? {
        return api.claimInvitation(ShareClaimRequest(invitationId))
    }

    suspend fun reportOutcome(report: ShareOutcomeReport): Boolean {
        return api.reportOutcome(report)
    }

    // --- NEW Revocation APIs (REST Standard) ---

    suspend fun revokeFriend(request: RevokeFriendRequest): RevokeFriendResponse? {
        return api.revokeFriend(request)
    }

    suspend fun fetchRevokeJobs(): List<RevokeJob> {
        return api.fetchRevokeJobs()
    }

    suspend fun reportRevokeJob(report: RevokeJobReport): Boolean {
        return api.reportRevokeJob(report)
    }

    // --- Sync & Management ---

    suspend fun syncKeyToCloud(email: String, record: CloudKeyRecord): Boolean {
        return api.syncKeyToCloud(email, record)
    }

    suspend fun fetchUserKeys(email: String): List<CloudKeyRecord> {
        return api.fetchUserKeys(email)
    }

    suspend fun revokeOwner(email: String, moduleID: String): Boolean {
        return api.revokeOwner(email, moduleID)
    }

    suspend fun revokeInvitation(senderEmail: String, recipientEmail: String, ap: ByteArray, signature: ByteArray?) {
        api.revokeInvitation(senderEmail, recipientEmail, ap, signature)
    }

    // --- Compatibility Methods ---

    suspend fun checkInvitationLegality(senderEmail: String, recipientEmail: String, parentKeyIdHex: String): String? {
        val res = checkSharingLegality(recipientEmail, parentKeyIdHex)
        return if (res?.isLegal == true) null else res?.message ?: "Check failed"
    }

    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        val request = ShareInviteRequest(
            recipientEmail = invitation.recipientEmail,
            moduleID = invitation.moduleID?.toHex() ?: "",
            parentKeyId = "", // Need to find a way to pass this if required by server
            ap_blob = invitation.ap.toHex(),
            pin_hash = "", // Legacy model doesn't have pin_hash separated
            car_metadata = invitation.carMetadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata()
        )
        return api.invite(request) != null
    }

    suspend fun reportInvitationOutcome(recipientEmail: String, ap: ByteArray, status: InvitationStatus, senderEmail: String) {
        val report = ShareOutcomeReport(
            invitationId = ap.toHex(),
            status = status.name
        )
        api.reportOutcome(report)
    }

    suspend fun notifyActivation(ap: ByteArray) {
        api.notifyActivation(ap)
    }
}

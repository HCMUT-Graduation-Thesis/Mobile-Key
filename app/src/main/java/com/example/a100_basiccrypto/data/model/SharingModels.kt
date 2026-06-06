package com.example.a100_basiccrypto.data.model

import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.google.gson.annotations.SerializedName

/**
 * 1. Legality Check Models
 */
data class ShareCheckRequest(
    val recipientEmail: String,
    val parentKeyId: String
)

data class ShareCheckResponse(
    val isLegal: Boolean,
    val message: String,
    val parentKeyId: String?,
    val moduleID: String?,
    val recipient: RecipientInfo?
)

data class RecipientInfo(
    val id: String,
    val email: String,
    @SerializedName("display_name") val displayName: String
)

/**
 * 2. Invite Models
 */
data class ShareInviteRequest(
    val recipientEmail: String,
    val moduleID: String,
    val parentKeyId: String,
    val ap_blob: String,
    val pin_hash: String,
    val car_metadata: CarMetadata
)

data class ShareInviteResponse(
    val message: String,
    val invitation: InvitationDetail
)

data class InvitationDetail(
    val id: String,
    val sender_id: String,
    val recipient_email: String,
    val module_id: String,
    val parent_key_id: String,
    val attestation_package: String,
    val pin_hash: String,
    val status: String,
    val metadata_snapshot: CarMetadata? = null,
    // CamelCase variants for Friend side
    val senderEmail: String? = null,
    val senderName: String? = null,
    val moduleID: String? = null,
    val parentKeyId: String? = null,
    val ap_blob: String? = null,
    val car_metadata: CarMetadata? = null
)

/**
 * 4. Claim Models
 */
data class ShareClaimRequest(
    val invitationId: String
)

/**
 * 5. Outcome Report Models
 */
data class ShareOutcomeReport(
    @SerializedName("invitation_id") val invitationId: String,
    val status: String, // "CLAIMED" or "FAILED"
    
    // Data collected from Vehicle after pairing
    val keyId: String? = null,
    val devicePublicKey: String? = null,
    val vehiclePublicKey: String? = null,
    val permissions: Int? = null,
    val validityStart: Long? = null,
    val validityEnd: Long? = null,
    val usageLimit: Int? = null,
    val keyState: String? = null,
    val holderNickname: String? = null
)

/**
 * 6. Revocation Models (Standardized)
 */
data class RevokeFriendRequest(
    val moduleID: String,
    val keyId: String? = null,
    val friendEmail: String? = null,
    val ownerSignature: String,
    val reason: String = "Owner revoked Friend key"
)

data class RevokeFriendResponse(
    val success: Boolean,
    val message: String,
    val flow: String?,
    val state: String?,
    val revokeJob: RevokeJob?,
    val vehicleCommand: VehicleCommand?,
    val friendSoftWipe: FriendSoftWipe?,
    val friendKey: InvitationDetail?
)

data class RevokeJob(
    val id: String,
    @SerializedName("key_id") val keyId: String,
    @SerializedName("module_id") val moduleId: String,
    @SerializedName("requester_email") val requesterEmail: String? = null,
    @SerializedName("requester_name") val requesterName: String? = null,
    @SerializedName("target_email") val targetEmail: String? = null,
    @SerializedName("target_name") val targetName: String? = null,
    val status: String,
    val reason: String? = null,
    @SerializedName("created_at") val createdAt: String? = null
)

data class VehicleCommand(
    val command: String,
    val transport: String,
    val payload: Map<String, String>
)

data class FriendSoftWipe(
    val targetUserId: String?,
    val targetEmail: String?,
    val keyId: String?,
    val moduleID: String?
)

data class RevokeJobReport(
    val jobId: String,
    val status: String, // "REVOKED", "FAILED", "DONE", "WIPED"
    val failureReason: String? = null
)

data class RevokeJobsResponse(
    val success: Boolean,
    val count: Int,
    val jobs: List<RevokeJob>
)

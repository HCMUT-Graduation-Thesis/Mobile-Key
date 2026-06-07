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
    @SerializedName(value = "id", alternate = ["invitation_id", "invitationId"])
    val id: String?,
    
    @SerializedName(value = "senderId", alternate = ["sender_id"])
    val senderId: String? = null,
    
    @SerializedName(value = "senderEmail", alternate = ["sender_email"])
    val senderEmail: String? = null,
    
    @SerializedName(value = "senderName", alternate = ["sender_name"])
    val senderName: String? = null,
    
    @SerializedName(value = "recipientEmail", alternate = ["recipient_email"])
    val recipientEmail: String? = null,
    
    @SerializedName(value = "moduleID", alternate = ["module_id", "moduleId"])
    val moduleID: String? = null,
    
    @SerializedName(value = "parentKeyId", alternate = ["parent_key_id"])
    val parentKeyId: String? = null,
    
    @SerializedName(value = "ap_blob", alternate = ["attestation_package"])
    val ap_blob: String? = null,
    
    @SerializedName(value = "pin_hash", alternate = ["pinHash"])
    val pin_hash: String? = null,
    
    val status: String = "PENDING",
    
    @SerializedName(value = "car_metadata", alternate = ["metadata_snapshot", "metadata"])
    val car_metadata: CarMetadata? = null,

    val createdAt: String? = null,
    val updatedAt: String? = null
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
    @SerializedName("invitation_id") val invitationId: String?,
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
 * 7. Sync Models (Standardized)
 */
data class SyncKeyRequest(
    val keyId: String,
    val moduleID: String,
    val parentKeyId: String? = null,
    val role: String, // "OWNER" or "FRIEND"
    val keyState: String, // "ACTIVE", "PROVISIONING", etc.
    val permissions: Int,
    val friendlyName: String,
    val holderNickname: String? = null,
    val devicePublicKey: String,
    val vehiclePublicKey: String,
    val validityStart: Long = 0,
    val validityEnd: Long = 0,
    val usageLimit: Int = 0,
    val metadata: CarMetadata? = null
)

data class SyncKeyResponse(
    val message: String,
    val key: SyncKeyDetail?
)

data class SyncKeyDetail(
    @SerializedName(value = "keyId", alternate = ["key_id"])
    val keyId: String,
    
    @SerializedName(value = "moduleID", alternate = ["module_id", "moduleId"])
    val moduleID: String,
    
    val ownerId: String? = null,
    val holderId: String? = null,
    
    @SerializedName(value = "parentKeyId", alternate = ["parent_key_id"])
    val parentKeyId: String? = null,
    
    val role: String,
    
    @SerializedName(value = "keyState", alternate = ["state", "key_state"])
    val keyState: String,
    
    val permissions: Int,
    
    @SerializedName(value = "friendlyName", alternate = ["friendly_name"])
    val friendlyName: String? = null,
    
    @SerializedName(value = "devicePublicKey", alternate = ["device_pk"])
    val devicePublicKey: String,
    
    @SerializedName(value = "vehiclePublicKey", alternate = ["vehicle_pk"])
    val vehiclePublicKey: String,
    
    val validityStart: Long = 0,
    val validityEnd: Long = 0,
    val usageLimit: Int = 0,
    
    @SerializedName(value = "metadata", alternate = ["car_metadata"])
    val metadata: CarMetadata? = null,
    
    val eKeys: List<SyncKeyDetail>? = null
)
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

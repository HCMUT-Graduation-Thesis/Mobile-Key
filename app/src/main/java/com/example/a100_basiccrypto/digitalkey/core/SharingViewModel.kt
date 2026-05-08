package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.NotificationStore
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.model.Role
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class SharingViewModel(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val authManager: AuthManager
) : ViewModel() {

    private val sharingManager = SharingManager(identityCrypto, storageManager)

    private val _uiState = MutableStateFlow<SharingUiState>(SharingUiState.Idle)
    val uiState: StateFlow<SharingUiState> = _uiState

    // Event flow for one-time events like showing a dialog or finishing activity
    private val _events = MutableSharedFlow<SharingEvent>()
    val events: SharedFlow<SharingEvent> = _events.asSharedFlow()

    // Flow for observing proactive invitations from Server (Stage 1 Push)
    val incomingInvitations = MockKeyServer.invitationFlow

    // Flow for the Owner to observe status updates of their sent invitations
    val sentInvitationUpdates = MockKeyServer.statusUpdateFlow

    init {
        // Sync NotificationStore with current user on initialization
        authManager.getUserEmail()?.let { email ->
            NotificationStore.setCurrentUser(email)
        }

        // FRIEND SIDE: Listen for REVOKED signals from server to perform soft-wipe
        observeRevocations()

        // OWNER SIDE: Listen for ACTIVATION signals from server
        observeActivations()
    }

    private fun observeRevocations() {
        viewModelScope.launch {
            MockKeyServer.statusUpdateFlow.collectLatest { update ->
                if (update.status == InvitationStatus.REVOKED) {
                    val currentEmail = authManager.getUserEmail()
                    // If the revocation is for the current user
                    if (update.recipientEmail.equals(currentEmail, ignoreCase = true)) {
                        Log.w("SharingViewModel", "🚨 [REVOKE] Received revocation signal for recipient: ${update.recipientEmail}")

                        // Perform Soft-Wipe: Find local key by AP and delete it
                        val allKeys = storageManager.getAllKeys()
                        val keyToDelete = allKeys.find { it.attestationPackage?.contentEquals(update.ap) == true }
                        
                        keyToDelete?.core?.keyID?.let { keyId ->
                            storageManager.deleteKey(keyId)
                            Log.i("SharingViewModel", "🗑️ [REVOKE] Local key deleted successfully.")
                            _uiState.value = SharingUiState.Error("A key was revoked by the owner.")
                            _events.emit(SharingEvent.KeyRevoked(keyId))
                        }
                    }
                }
            }
        }
    }

    private fun observeActivations() {
        viewModelScope.launch {
            MockKeyServer.activationFlow.collectLatest { activatedAp ->
                Log.d("SharingViewModel", "⚡ [ACTIVATE] Signal received for an AP. Updating local state...")
                val allKeys = storageManager.getAllKeys()
                var found = false
                allKeys.forEach { key ->
                    if (key.core.keyState == KeyState.PENDING && key.attestationPackage?.contentEquals(activatedAp) == true) {
                        key.core.keyState = KeyState.ACTIVE
                        storageManager.saveDigitalKey(key)
                        found = true
                        Log.i("SharingViewModel", "✅ [ACTIVATE] Local Pending key for ${key.keyHolderName} is now ACTIVE.")
                    }
                }
                if (found) {
                    _events.emit(SharingEvent.RemoteActivationSuccess)
                }
            }
        }
    }

    /**
     * OWNER SIDE: Stage 1.1 - Check and Share key.
     */
    fun shareKey(
        ownerRecord: DigitalKeyRecord,
        permissions: Int,
        validityDays: Int,
        usageLimit: Int = 0,
        daysOfWeek: Int = 0,
        startTimeMinutes: Int = -1,
        endTimeMinutes: Int = -1,
        holderNickname: String = "",
        recipientEmail: String = "",
        senderEmail: String = ""
    ) {
        viewModelScope.launch {
            _uiState.value = SharingUiState.Loading

            // 1. Security Check with Server
            val parentKeyIdHex = ownerRecord.core.keyID?.toHex() ?: ""
            val errorMsg = MockKeyServer.checkInvitationLegality(senderEmail, recipientEmail, parentKeyIdHex)
            
            if (errorMsg != null) {
                _uiState.value = SharingUiState.Error(errorMsg)
                return@launch
            }

            // 2. Proceed to create and sign AP
            val updatedRecord = sharingManager.createInvitation(
                ownerRecord = ownerRecord,
                role = Role.FRIEND,
                permissions = permissions,
                validityDays = validityDays,
                usageLimit = usageLimit,
                daysOfWeek = daysOfWeek,
                startTimeMinutes = startTimeMinutes,
                endTimeMinutes = endTimeMinutes,
                holderNickname = holderNickname,
                recipientEmail = recipientEmail,
                senderName = "Owner Device"
            )
            
            if (updatedRecord != null) {
                _uiState.value = SharingUiState.ShareSuccess(updatedRecord.invitationCode ?: "")
            } else {
                _uiState.value = SharingUiState.Error("Failed to create invitation package.")
            }
        }
    }

    /**
     * OWNER SIDE: Revokes a previously shared key (Friend Revocation).
     * Updated to support Local Phase (Vehicle) and Sync Phase (Cloud) as per 1.1 spec.
     */
    fun revokeKey(record: DigitalKeyRecord) {
        viewModelScope.launch {
            val ap = record.attestationPackage ?: return@launch
            val recipientEmail = record.accountEmail ?: return@launch
            val senderEmail = authManager.getUserEmail() ?: return@launch
            val friendKeyID = record.core.keyID ?: return@launch

            _uiState.value = SharingUiState.Loading

            // 1. Identification: Get Owner key authority
            val parentKeyID = record.core.parentKeyID ?: return@launch
            val ownerRecord = storageManager.getDigitalKey(parentKeyID)
            val ownerSK = ownerRecord?.devicePrivateKey ?: return@launch

            // 2. LOCAL PHASE: Add to pending queue for vehicle removal (via INS_REMOVE_FRIEND)
            Log.d("SharingViewModel", "🛡️ [REVOKE-LOCAL] Queuing FriendID=${friendKeyID.toHex()} for removal at Vehicle.")
            storageManager.addPendingRevocation(parentKeyID, friendKeyID)

            // 3. SYNC PHASE: Online Revocation with Proof of Intent (Signature)
            val revokeSignature = identityCrypto.sign(ap, ownerSK)
            Log.i("SharingViewModel", "☁️ [REVOKE-SYNC] Notifying Cloud for recipient $recipientEmail")
            
            // Notify Server
            MockKeyServer.revokeInvitation(senderEmail, recipientEmail, ap, revokeSignature)
            
            // 4. CLEANUP: Remove from Owner's local share list
            storageManager.deleteKey(friendKeyID)
            
            _uiState.value = SharingUiState.RevokeSuccess
            _events.emit(SharingEvent.LocalRevokeSuccess)
        }
    }

    /**
     * FRIEND SIDE: Stage 1.2 - Fetch missed invitations from Server (Inbox).
     */
    fun fetchInvitationsFromCloud(email: String) {
        viewModelScope.launch {
            val pendingList = MockKeyServer.fetchPendingInvitations(email)
            pendingList.forEach { invitation ->
                NotificationStore.addNotification(
                    ownerEmail = email,
                    title = "Missed Key Shared",
                    message = "${invitation.senderName} shared a key with you.",
                    invitation = invitation
                )
            }
        }
    }

    fun onInvitationReceived(invitation: ShareInvitation): DigitalKeyRecord? {
        val record = sharingManager.processIncomingInvitation(invitation)
        if (record != null) {
            _uiState.value = SharingUiState.ReceivedInvitation(record, invitation)
        }
        return record
    }

    /**
     * FRIEND SIDE: Verify PIN with attempt counting and report results to server.
     */
    fun verifyPinAndActivate(record: DigitalKeyRecord, pin: String, invitation: ShareInvitation) {
        viewModelScope.launch {
            _uiState.value = SharingUiState.Loading
            val success = sharingManager.verifyPinAndFinalize(record, pin)
            if (success) {
                // Success: Report CLAIMED status to server
                MockKeyServer.reportInvitationOutcome(
                    recipientEmail = record.accountEmail ?: "",
                    ap = record.attestationPackage ?: byteArrayOf(),
                    status = InvitationStatus.CLAIMED,
                    senderEmail = invitation.senderEmail
                )

                MockKeyServer.notifyActivation(record.attestationPackage ?: byteArrayOf())
                NotificationStore.markAsUsed(invitation)
                _uiState.value = SharingUiState.ActivationSuccess
            } else {
                // Failure: Increment attempts
                val attempts = NotificationStore.incrementAttempts(invitation)
                if (attempts >= 3) {
                    // Report FAILED status to server
                    MockKeyServer.reportInvitationOutcome(
                        recipientEmail = record.accountEmail ?: "",
                        ap = record.attestationPackage ?: byteArrayOf(),
                        status = InvitationStatus.FAILED,
                        senderEmail = invitation.senderEmail
                    )
                    _uiState.value = SharingUiState.Error("Too many failed attempts. Invitation cancelled.")
                } else {
                    _uiState.value = SharingUiState.Error("Invalid PIN code. ${3 - attempts} attempts left.")
                }
            }
        }
    }

    fun resetState() {
        _uiState.value = SharingUiState.Idle
    }

    sealed class SharingUiState {
        object Idle : SharingUiState()
        object Loading : SharingUiState()
        object RevokeSuccess : SharingUiState()
        data class ShareSuccess(val code: String) : SharingUiState()
        data class ReceivedInvitation(val record: DigitalKeyRecord, val invitation: ShareInvitation) : SharingUiState()
        object ActivationSuccess : SharingUiState()
        data class Error(val message: String) : SharingUiState()
    }
    
    sealed class SharingEvent {
        object RemoteActivationSuccess : SharingEvent()
        object LocalRevokeSuccess : SharingEvent()
        data class KeyRevoked(val keyId: ByteArray) : SharingEvent()
    }
}

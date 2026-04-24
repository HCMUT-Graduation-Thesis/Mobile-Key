package com.example.a100_basiccrypto.digitalkey.core

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.NotificationStore
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.model.Role
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class SharingViewModel(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val authManager: AuthManager // Added to track current user
) : ViewModel() {

    private val sharingManager = SharingManager(identityCrypto, storageManager)

    private val _uiState = MutableStateFlow<SharingUiState>(SharingUiState.Idle)
    val uiState: StateFlow<SharingUiState> = _uiState

    // Flow for observing proactive invitations from Server (Stage 1 Push)
    val incomingInvitations = MockKeyServer.invitationFlow
    
    // Flow for the Owner to observe status updates of their sent invitations
    val sentInvitationUpdates = MockKeyServer.statusUpdateFlow

    init {
        // Sync NotificationStore with current user on initialization
        authManager.getUserEmail()?.let { email ->
            NotificationStore.setCurrentUser(email)
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
        friendlyName: String = "",
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
                friendlyName = friendlyName,
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
     * FRIEND SIDE: Stage 1.2 - Fetch missed invitations from Server (Inbox).
     */
    fun fetchInvitationsFromCloud(email: String) {
        viewModelScope.launch {
            val pendingList = MockKeyServer.fetchPendingInvitations(email)
            pendingList.forEach { invitation ->
                // Add to notification store managed by user email
                NotificationStore.addNotification(
                    ownerEmail = email,
                    title = "Missed Key Shared",
                    message = "${invitation.senderName} shared ${invitation.friendlyName} with you.",
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
        data class ShareSuccess(val code: String) : SharingUiState()
        data class ReceivedInvitation(val record: DigitalKeyRecord, val invitation: ShareInvitation) : SharingUiState()
        object ActivationSuccess : SharingUiState()
        data class Error(val message: String) : SharingUiState()
    }
}

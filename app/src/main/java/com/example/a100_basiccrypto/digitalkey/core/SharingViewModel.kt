package com.example.a100_basiccrypto.digitalkey.core

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.model.Role
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class SharingViewModel(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager
) : ViewModel() {

    private val sharingManager = SharingManager(identityCrypto, storageManager)

    private val _uiState = MutableStateFlow<SharingUiState>(SharingUiState.Idle)
    val uiState: StateFlow<SharingUiState> = _uiState

    // Flow for observing proactive invitations from Server (Stage 1)
    val incomingInvitations = MockKeyServer.invitationFlow

    /**
     * Stage 1.1: Owner creates and uploads invitation to Server.
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
        recipientEmail: String = ""
    ) {
        viewModelScope.launch {
            _uiState.value = SharingUiState.Loading
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
                _uiState.value = SharingUiState.ShareSuccess(
                    updatedRecord.invitationCode ?: ""
                )
            } else {
                _uiState.value = SharingUiState.Error("Failed to create invitation")
            }
        }
    }

    /**
     * Stage 1.3: Friend receives push invitation and starts verification.
     */
    fun onInvitationReceived(invitation: ShareInvitation) {
        val record = sharingManager.processIncomingInvitation(invitation)
        if (record != null) {
            // Transition to state where UI shows PIN input dialog
            _uiState.value = SharingUiState.ReceivedInvitation(record)
        }
    }

    /**
     * Stage 1.4: Finalize local record after PIN verification.
     */
    fun verifyPinAndActivate(record: DigitalKeyRecord, pin: String) {
        viewModelScope.launch {
            _uiState.value = SharingUiState.Loading
            val success = sharingManager.verifyPinAndFinalize(record, pin)
            if (success) {
                // Mock: Notify server that the key is successfully claimed (optional)
                MockKeyServer.notifyActivation(record.attestationPackage ?: byteArrayOf())
                _uiState.value = SharingUiState.ActivationSuccess
            } else {
                _uiState.value = SharingUiState.Error("Invalid PIN code. Please try again.")
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
        data class ReceivedInvitation(val record: DigitalKeyRecord) : SharingUiState()
        object ActivationSuccess : SharingUiState()
        data class Error(val message: String) : SharingUiState()
    }
}

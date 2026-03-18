package com.example.a100_basiccrypto.digitalkey.core

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
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

    // Flow for listening to incoming invitations from Mock Server
    val incomingInvitations = MockKeyServer.invitationFlow

    fun shareKey(
        ownerRecord: DigitalKeyRecord,
        permissions: Int,
        validityDays: Int
    ) {
        viewModelScope.launch {
            _uiState.value = SharingUiState.Loading
            val updatedRecord = sharingManager.createInvitation(
                ownerRecord,
                Role.FRIEND,
                permissions,
                validityDays
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

    fun processInvitation(ap: ByteArray) {
        viewModelScope.launch {
            val record = sharingManager.processIncomingInvitation(ap)
            if (record != null) {
                _uiState.value = SharingUiState.ReceivedInvitation(record)
            }
        }
    }

    fun simulatePush() {
        viewModelScope.launch {
            val ap = MockKeyServer.downloadAP()
            if (ap != null) {
                processInvitation(ap)
            }
        }
    }

    fun clearMockServer() {
        MockKeyServer.reset()
    }

    fun resetState() {
        _uiState.value = SharingUiState.Idle
    }

    sealed class SharingUiState {
        object Idle : SharingUiState()
        object Loading : SharingUiState()
        data class ShareSuccess(val code: String) : SharingUiState()
        data class ReceivedInvitation(val record: DigitalKeyRecord) : SharingUiState()
        data class Error(val message: String) : SharingUiState()
    }
}

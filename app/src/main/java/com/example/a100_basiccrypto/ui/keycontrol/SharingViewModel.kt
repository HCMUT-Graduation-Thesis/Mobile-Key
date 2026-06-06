package com.example.a100_basiccrypto.ui.keycontrol

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.data.local.NotificationStore
import com.example.a100_basiccrypto.data.model.*
import com.example.a100_basiccrypto.data.repository.AuthRepository
import com.example.a100_basiccrypto.data.repository.KeyRepository
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.SharingManager
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.StandardTransactionClient
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.hexToBytes
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class SharingViewModel(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val authManager: AuthManager,
    private val authRepository: AuthRepository,
    private val keyRepository: KeyRepository
) : ViewModel() {

    companion object {
        private const val TAG = "SharingViewModel"
    }

    private val sharingManager = SharingManager(identityCrypto, storageManager)

    private val _uiState = MutableStateFlow<SharingUiState>(SharingUiState.Idle)
    val uiState: StateFlow<SharingUiState> = _uiState

    private val _events = MutableSharedFlow<SharingEvent>()
    val events: SharedFlow<SharingEvent> = _events.asSharedFlow()

    val incomingInvitations = keyRepository.invitationFlow

    init {
        authManager.getUserEmail()?.let { email ->
            NotificationStore.setCurrentUser(email)
        }
        observeRevocations()
        observeActivations()
    }

    private fun observeRevocations() {
        viewModelScope.launch {
            keyRepository.statusUpdateFlow.collectLatest { update ->
                Log.d(TAG, "📡 [REVOKE-OBSERVER] Received status update: ${update.status} for ${update.recipientEmail}")
                if (update.status == InvitationStatus.REVOKED) {
                    val currentEmail = authManager.getUserEmail()
                    if (update.recipientEmail.equals(currentEmail, ignoreCase = true)) {
                        val allKeys = storageManager.getAllKeys()
                        val keyToDelete = allKeys.find { it.attestationPackage?.contentEquals(update.ap) == true }
                        keyToDelete?.core?.keyID?.let { keyId ->
                            Log.i(TAG, "🗑️ [REVOKE-LOCAL] Deleting revoked key locally: ${keyId.toHex()}")
                            storageManager.deleteKey(keyId)
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
            keyRepository.activationFlow.collectLatest { activatedAp ->
                Log.d(TAG, "📡 [ACTIVATE-OBSERVER] Received activation notification for AP: ${activatedAp.toHex()}")
                val allKeys = storageManager.getAllKeys()
                var found = false
                allKeys.forEach { key ->
                    if (key.core.keyState == KeyState.PENDING && key.attestationPackage?.contentEquals(activatedAp) == true) {
                        Log.i(TAG, "✅ [ACTIVATE-LOCAL] Marking key ${key.core.keyID?.toHex()} as ACTIVE (Remote update)")
                        key.core.keyState = KeyState.ACTIVE
                        storageManager.saveDigitalKey(key)
                        found = true
                    }
                }
                if (found) {
                    _events.emit(SharingEvent.RemoteActivationSuccess)
                }
            }
        }
    }

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
            Log.i(TAG, "📤 [SHARE] Starting sharing flow for recipient: $recipientEmail")
            _uiState.value = SharingUiState.Loading

            val parentKeyIdHex = ownerRecord.core.keyID?.toHex() ?: ""
            Log.d(TAG, "🔍 [SHARE-CHECK] Checking sharing legality for $recipientEmail...")
            val checkRes = keyRepository.checkSharingLegality(recipientEmail, parentKeyIdHex)
            
            if (checkRes == null || !checkRes.isLegal) {
                Log.e(TAG, "❌ [SHARE-CHECK] Legality check failed: ${checkRes?.message ?: "Unknown error"}")
                _uiState.value = SharingUiState.Error(checkRes?.message ?: "Legality check failed")
                return@launch
            }
            Log.d(TAG, "✅ [SHARE-CHECK] Legality check passed. ModuleID: ${checkRes.moduleID}")

            Log.d(TAG, "🛠️ [SHARE-GEN] Creating invitation package (AP)...")
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
                val inviteReq = ShareInviteRequest(
                    recipientEmail = recipientEmail,
                    moduleID = updatedRecord.moduleID!!.toHex(),
                    parentKeyId = parentKeyIdHex,
                    ap_blob = updatedRecord.attestationPackage!!.toHex(),
                    pin_hash = updatedRecord.invitationCodeHash!!.toHex(),
                    car_metadata = updatedRecord.carMetadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata(
                        modelName = updatedRecord.friendlyName
                    )
                )
                
                Log.d(TAG, "☁️ [SHARE-UPLOAD] Uploading invitation to Cloud...")
                val inviteRes = keyRepository.sendInvitation(inviteReq)
                if (inviteRes != null) {
                    Log.i(TAG, "🎉 [SHARE-SUCCESS] Invitation uploaded! PIN Code: ${updatedRecord.invitationCode}")
                    _uiState.value = SharingUiState.ShareSuccess(updatedRecord.invitationCode ?: "")
                } else {
                    Log.e(TAG, "❌ [SHARE-UPLOAD] Failed to upload invitation to server.")
                    _uiState.value = SharingUiState.Error("Failed to upload invitation to server.")
                }
            } else {
                Log.e(TAG, "❌ [SHARE-GEN] Failed to create invitation package.")
                _uiState.value = SharingUiState.Error("Failed to create invitation package.")
            }
        }
    }

    fun onInvitationReceived(invitation: InvitationDetail): DigitalKeyRecord? {
        Log.i(TAG, "📩 [RECV] Processing received invitation: ${invitation.id} from ${invitation.senderName}")
        val legacyInv = mapToLegacy(invitation)
        val record = sharingManager.processIncomingInvitation(legacyInv)
        if (record != null) {
            Log.d(TAG, "📦 [RECV-LOCAL] Temporary record created for key: ${record.core.keyID?.toHex()}")
            _uiState.value = SharingUiState.ReceivedInvitation(record, invitation)
        } else {
            Log.e(TAG, "❌ [RECV-ERROR] Failed to process AP from invitation.")
        }
        return record
    }

    fun verifyPinAndActivate(record: DigitalKeyRecord, pin: String, invitation: InvitationDetail) {
        viewModelScope.launch {
            Log.i(TAG, "🔑 [ACTIVATE] Verifying PIN for key: ${record.core.keyID?.toHex()}")
            _uiState.value = SharingUiState.Loading
            val success = sharingManager.verifyPinAndFinalize(record, pin)
            
            if (success) {
                Log.i(TAG, "✅ [ACTIVATE-PIN] PIN correct. Reporting outcome to Cloud...")
                val report = ShareOutcomeReport(
                    invitationId = invitation.id,
                    status = "CLAIMED",
                    keyId = record.core.keyID?.toHex(),
                    devicePublicKey = record.devicePublicKey?.toHex(),
                    vehiclePublicKey = record.vehiclePublicKey?.toHex(),
                    permissions = record.core.permissions,
                    keyState = "ACTIVE",
                    holderNickname = authManager.getUserName()
                )
                keyRepository.reportOutcome(report)
                keyRepository.notifyActivation(record.attestationPackage ?: byteArrayOf())
                _uiState.value = SharingUiState.ActivationSuccess
                NotificationStore.markAsUsed(invitation)
            } else {
                val attempts = NotificationStore.incrementAttempts(invitation)
                Log.w(TAG, "❌ [ACTIVATE-PIN] Invalid PIN. Attempt $attempts/3")
                if (attempts >= 3) {
                    Log.e(TAG, "🚫 [ACTIVATE-FAIL] Max attempts reached. Reporting FAILURE to Cloud.")
                    keyRepository.reportOutcome(ShareOutcomeReport(invitation.id, "FAILED"))
                    _uiState.value = SharingUiState.Error("Too many failed attempts. Key rejected.")
                } else {
                    _uiState.value = SharingUiState.Error("Invalid PIN code. Attempt $attempts/3")
                }
            }
        }
    }

    private fun mapToLegacy(inv: InvitationDetail): ShareInvitation {
        return ShareInvitation(
            ap = inv.attestation_package.hexToBytes(),
            friendlyName = inv.car_metadata?.modelName ?: "New Car",
            recipientEmail = authManager.getUserEmail() ?: "",
            senderName = inv.senderName ?: "Owner",
            senderEmail = inv.senderEmail ?: "",
            carMetadata = inv.car_metadata,
            moduleID = inv.moduleID?.hexToBytes()
        )
    }

    fun revokeKey(record: DigitalKeyRecord) {
        viewModelScope.launch {
            val ap = record.attestationPackage ?: return@launch
            val recipientEmail = record.accountEmail ?: return@launch
            val senderEmail = authManager.getUserEmail() ?: return@launch
            val friendKeyID = record.core.keyID ?: return@launch

            Log.i(TAG, "🛑 [REVOKE] Initiating revocation for Friend Key: ${friendKeyID.toHex()}")
            _uiState.value = SharingUiState.Loading
            val parentKeyID = record.core.parentKeyID ?: return@launch
            val ownerSK = identityCrypto.getPrivateKey()

            Log.d(TAG, "⚙️ [REVOKE-QUEUE] Adding Friend Key to pending local removal queue...")
            storageManager.addPendingRevocation(parentKeyID, friendKeyID)
            
            val revokeSignature = identityCrypto.sign(ap, ownerSK)
            Log.d(TAG, "☁️ [REVOKE-CLOUD] Sending revocation to Cloud...")
            keyRepository.revokeInvitation(senderEmail, recipientEmail, ap, revokeSignature)
            
            Log.d(TAG, "🗑️ [REVOKE-CLEAN] Deleting Friend Record from Owner's local storage.")
            storageManager.deleteKey(friendKeyID)
            
            _uiState.value = SharingUiState.RevokeSuccess
            _events.emit(SharingEvent.LocalRevokeSuccess)
        }
    }

    fun revokeOwnerSelf(record: DigitalKeyRecord, password: String) {
        viewModelScope.launch {
            _uiState.value = SharingUiState.Loading
            val email = authManager.getUserEmail() ?: ""
            val authResult = authRepository.login(email, password)
            if (!authResult) {
                _uiState.value = SharingUiState.Error("Authentication failed.")
                return@launch
            }

            val transport = BleProvider.getTransport()
            if (transport == null) {
                _uiState.value = SharingUiState.Error("BLE disconnected.")
                return@launch
            }

            val standardTxClient = StandardTransactionClient(storageManager, identityCrypto) { }
            val localSuccess = standardTxClient.executeRevokeOwner(transport, record.core.keyID!!)

            if (localSuccess) {
                val moduleIDHex = record.moduleID?.toHex() ?: ""
                if (keyRepository.revokeOwner(email, moduleIDHex)) {
                    storageManager.deleteKey(record.core.keyID!!)
                    _uiState.value = SharingUiState.RevokeSuccess
                    _events.emit(SharingEvent.LocalRevokeSuccess)
                }
            } else {
                _uiState.value = SharingUiState.Error("Vehicle reset failed.")
            }
        }
    }

    fun fetchInvitationsFromCloud(email: String) {
        viewModelScope.launch {
            Log.d(TAG, "☁️ [FETCH] Fetching pending invitations for $email from Cloud...")
            val pendingList = keyRepository.fetchPendingInvitations(email)
            Log.i(TAG, "📥 [FETCH] Received ${pendingList.size} invitations from Cloud.")
            pendingList.forEach { invitation ->
                NotificationStore.addNotification(email, "Key Shared", "Shared by ${invitation.senderName}", invitation)
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
        data class ReceivedInvitation(val record: DigitalKeyRecord, val invitation: InvitationDetail) : SharingUiState()
        object ActivationSuccess : SharingUiState()
        data class Error(val message: String) : SharingUiState()
    }
    
    sealed class SharingEvent {
        object RemoteActivationSuccess : SharingEvent()
        object LocalRevokeSuccess : SharingEvent()
        data class KeyRevoked(val keyId: ByteArray) : SharingEvent()
    }
}

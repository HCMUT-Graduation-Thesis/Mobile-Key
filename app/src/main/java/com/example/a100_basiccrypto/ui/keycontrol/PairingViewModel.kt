package com.example.a100_basiccrypto.ui.keycontrol

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.data.model.SyncKeyRequest
import com.example.a100_basiccrypto.data.repository.KeyRepository
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.model.SyncStatus
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PairingViewModel(
    private val storageManager: SecureKeyStorageManager,
    private val keyRepository: KeyRepository,
    private val identityCrypto: IIdentityCrypto
) : ViewModel() {

    fun startBackgroundSync(email: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val allKeys = storageManager.getAllKeys()
            val latestKey = allKeys.maxByOrNull { it.core.validityStart } ?: return@launch

            // 1. Tag locally
            latestKey.accountEmail = email
            latestKey.syncStatus = SyncStatus.PENDING_UPLOAD
            storageManager.saveDigitalKey(latestKey)

            try {
                // 2. Prepare Standardized Sync Request
                val syncReq = SyncKeyRequest(
                    keyId = latestKey.core.keyID?.toHex() ?: "unknown",
                    moduleID = latestKey.moduleID?.toHex() ?: "unknown",
                    parentKeyId = latestKey.core.parentKeyID?.toHex(),
                    role = latestKey.core.role.name,
                    keyState = latestKey.core.keyState.name,
                    permissions = latestKey.core.permissions,
                    friendlyName = latestKey.friendlyName.ifEmpty { latestKey.carMetadata?.modelName ?: "My Vehicle" },
                    holderNickname = latestKey.keyHolderName,
                    devicePublicKey = identityCrypto.getPublicKey().toHex(),
                    vehiclePublicKey = latestKey.vehiclePublicKey?.toHex() ?: "",
                    validityStart = latestKey.core.validityStart,
                    validityEnd = latestKey.core.validityEnd,
                    usageLimit = latestKey.core.usageLimit,
                    metadata = latestKey.carMetadata
                )

                // 3. Sync to Cloud
                val response = keyRepository.uploadKey(syncReq)
                if (response != null) {
                    latestKey.syncStatus = SyncStatus.SYNCED
                    storageManager.saveDigitalKey(latestKey)
                    Log.i("PairingViewModel", "Standardized Cloud Sync Successful for ${latestKey.friendlyName}")
                }
            } catch (e: Exception) {
                Log.e("PairingViewModel", "Background Sync failed: ${e.message}")
            }
        }
    }
}

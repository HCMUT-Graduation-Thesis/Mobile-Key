package com.example.a100_basiccrypto.ui.keycontrol

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.data.model.CloudKeyRecord
import com.example.a100_basiccrypto.data.repository.KeyRepository
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.model.SyncStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PairingViewModel(
    private val storageManager: SecureKeyStorageManager,
    private val keyRepository: KeyRepository
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
                // 2. Prepare Cloud Record
                val cloudRecord = CloudKeyRecord(
                    keyId = latestKey.core.keyID?.toHex() ?: "unknown",
                    moduleID = latestKey.moduleID?.toHex() ?: "unknown",
                    ownerEmail = email,
                    holderEmail = email,
                    parentKeyId = null,
                    devicePublicKey = latestKey.devicePublicKey?.toHex() ?: "",
                    vehiclePublicKey = latestKey.vehiclePublicKey?.toHex() ?: "",
                    role = latestKey.core.role,
                    permissions = latestKey.core.permissions,
                    keyState = latestKey.core.keyState,
                    validityStart = latestKey.core.validityStart,
                    validityEnd = latestKey.core.validityEnd,
                    usageLimit = latestKey.core.usageLimit,
                    friendlyName = latestKey.friendlyName.ifEmpty { latestKey.carMetadata?.modelName ?: "My Vehicle" },
                    metadata = latestKey.carMetadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata(
                        modelName = "New Vehicle",
                        licensePlate = "PENDING"
                    )
                )

                // 3. Sync to Cloud
                val success = keyRepository.syncKeyToCloud(email, cloudRecord)
                if (success) {
                    latestKey.syncStatus = SyncStatus.SYNCED
                    storageManager.saveDigitalKey(latestKey)
                    Log.i("PairingViewModel", "Background Sync Successful for ${latestKey.friendlyName}")
                }
            } catch (e: Exception) {
                Log.e("PairingViewModel", "Background Sync failed: ${e.message}")
            }
        }
    }
}

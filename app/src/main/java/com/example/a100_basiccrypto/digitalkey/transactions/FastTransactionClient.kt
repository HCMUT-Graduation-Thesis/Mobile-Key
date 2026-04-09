package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.IActiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import java.nio.ByteBuffer

/**
 * FastTransactionClient - Handles ACTIVE (Initiator) flow for BLE transactions.
 * Refactored to fetch fresh data from storage to ensure counter synchronization.
 */
class FastTransactionClient(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "FastTxClient"
    }

    /**
     * Executes the entire fast transaction flow.
     * Fetches the latest record from DB to prevent stale counter issues (e.g., after an NFC tx).
     */
    suspend fun execute(
        transport: IActiveTransport,
        keyID: ByteArray, // Pass KeyID instead of potentially stale Record
        msgClass: Byte,
        targetIns: Byte
    ): Boolean {
        try {
            // 1. Fetch FRESH record from Database right before execution
            val record = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(keyID) == true }
                ?: run {
                    onLog("BLE Error: Key not found in storage")
                    return false
                }

            onLog("BLE: Initiating action (Current Counter in DB: ${record.core.transactionCounter})")

            // 2. Increment and persist new counter (Update-Before-Send)
            val nextCounter = record.core.transactionCounter + 1
            storageManager.updateTransactionCounter(keyID, nextCounter)
            record.core.transactionCounter = nextCounter // Update local copy for current flow

            // 3. Prepare Request
            val authPayload = prepareActionRequest(record, targetIns, nextCounter) ?: return false
            
            // 4. Transmission
            val frame = LogicalFrame(msgClass, targetIns, authPayload)
            val response = transport.exchange(frame)

            // 5. Process Response
            return if (response.status == Status.SUCCESS) {
                verifyCommitMarker(record, response.data)
            } else {
                onLog("BLE Error: Vehicle rejected request (Status: 0x%02X)".format(response.status))
                false
            }
        } catch (e: Exception) {
            onLog("BLE Error: Flow interrupted - ${e.message}")
            return false
        }
    }

    private fun prepareActionRequest(record: DigitalKeyRecord, targetIns: Byte, counter: Int): ByteArray? {
        try {
            if (record.core.keyState != KeyState.ACTIVE) return null

            val fastAuthKey = record.core.fastAuthKey ?: return null
            val keyID = record.core.keyID ?: return null

            val isEngineCmd = (targetIns == Fast.INS_START_ENGINE || targetIns == Fast.INS_STOP_ENGINE)
            val payloadSize = 4 + (if (isEngineCmd) CryptoConstants.IMMOBILIZER_TOKEN_SIZE else 0)
            
            val plainPayload = ByteBuffer.allocate(payloadSize).apply {
                putInt(counter)
                if (isEngineCmd) put(record.immobilizerToken ?: ByteArray(64))
            }.array()

            val encrypted = CryptoUtils.encryptAesGcm(plainPayload, fastAuthKey)

            return ByteBuffer.allocate(keyID.size + encrypted.size).apply {
                put(keyID)
                put(encrypted)
            }.array()

        } catch (e: Exception) {
            Log.e(TAG, "Request Preparation Error: ${e.message}")
            return null
        }
    }

    private fun verifyCommitMarker(record: DigitalKeyRecord, encryptedResponse: ByteArray): Boolean {
        val fastAuthKey = record.core.fastAuthKey ?: return false
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(encryptedResponse, fastAuthKey)
            decrypted.isNotEmpty() && decrypted[0] == 0x00.toByte()
        } catch (e: Exception) {
            false
        }
    }
}

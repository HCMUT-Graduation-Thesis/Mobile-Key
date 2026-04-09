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
 * Orchestrates the full process with "Update-Before-Send" policy for counter reliability.
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
     * Increments and saves the counter BEFORE sending to prevent Replay Attack errors
     * if the response is lost but the vehicle processed the command.
     */
    suspend fun execute(
        transport: IActiveTransport,
        record: DigitalKeyRecord,
        msgClass: Byte,
        targetIns: Byte
    ): Boolean {
        try {
            onLog("BLE: Initiating action (INS: 0x%02X)".format(targetIns))

            // 1. Calculate and persist new counter immediately (Burn the counter)
            val nextCounter = record.core.transactionCounter + 1
            storageManager.updateTransactionCounter(record.core.keyID!!, nextCounter)
            
            // Update the local record object to reflect the change for this session
            record.core.transactionCounter = nextCounter

            // 2. Prepare Request (Phase 2 in spec) using the new counter
            val authPayload = prepareActionRequest(record, targetIns, nextCounter) ?: return false
            
            // 3. Exchange (Transmission)
            val frame = LogicalFrame(msgClass, targetIns, authPayload)
            val response = transport.exchange(frame)

            // 4. Process Response (Phase 3 in spec)
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

    /**
     * Prepares the encrypted payload for an action request.
     */
    private fun prepareActionRequest(record: DigitalKeyRecord, targetIns: Byte, counter: Int): ByteArray? {
        try {
            if (record.core.keyState != KeyState.ACTIVE) {
                onLog("Error: Key is not ACTIVE")
                return null
            }

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

    /**
     * Just verifies the commit marker from the vehicle. 
     * DB is already updated in the initiation step.
     */
    private fun verifyCommitMarker(record: DigitalKeyRecord, encryptedResponse: ByteArray): Boolean {
        val fastAuthKey = record.core.fastAuthKey ?: return false
        
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(encryptedResponse, fastAuthKey)
            
            if (decrypted.isNotEmpty() && decrypted[0] == 0x00.toByte()) {
                onLog("BLE Fast Tx: Success confirmed by vehicle.")
                true
            } else {
                onLog("BLE Fast Tx Warning: Invalid Marker, but counter was updated.")
                false
            }
        } catch (e: Exception) {
            onLog("BLE Fast Tx Error: Response verification failed.")
            false
        }
    }
}

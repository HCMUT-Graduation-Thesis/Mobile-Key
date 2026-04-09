package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.model.KeyState
import java.nio.ByteBuffer

/**
 * FastTransactionClient - Handles ACTIVE (Initiator) flow for BLE transactions.
 * Follows the same security logic as the passive NFC flow but initiated by the App.
 */
class FastTransactionClient(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "FastTxClient"
    }

    /**
     * Prepares the encrypted payload for an action request (Phase 2 in spec).
     * @return The complete packet to send over BLE: [KeyID (8B)] + [CipherPayload]
     */
    fun prepareActionRequest(record: DigitalKeyRecord, targetIns: Byte): ByteArray? {
        try {
            if (record.core.keyState != KeyState.ACTIVE) {
                onLog("Error: Key is not ACTIVE")
                return null
            }

            val fastAuthKey = record.core.fastAuthKey ?: return null
            val keyID = record.core.keyID ?: return null

            // 1. Increment transaction counter
            val nextCounter = record.core.transactionCounter + 1
            
            // 2. Build Secret Payload: [Counter (4B)] + [ImmoToken (64B) if engine cmd]
            val isEngineCmd = (targetIns == Fast.INS_START_ENGINE || targetIns == Fast.INS_STOP_ENGINE)
            val payloadSize = 4 + (if (isEngineCmd) CryptoConstants.IMMOBILIZER_TOKEN_SIZE else 0)
            
            val plainPayload = ByteBuffer.allocate(payloadSize).apply {
                putInt(nextCounter)
                if (isEngineCmd) put(record.immobilizerToken ?: ByteArray(64))
            }.array()

            // 3. Encrypt using AES-GCM with fastAuthKey
            val encrypted = CryptoUtils.encryptAesGcm(plainPayload, fastAuthKey)

            // 4. Construct Final Packet: [KeyID (8B)] + [Encrypted Data]
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
     * Validates the commit marker from the vehicle (Phase 3 in spec).
     * If valid, updates the local database (Phase 4).
     */
    fun processCommitResponse(record: DigitalKeyRecord, encryptedResponse: ByteArray): Boolean {
        val fastAuthKey = record.core.fastAuthKey ?: return false
        
        return try {
            // 1. Decrypt response
            val decrypted = CryptoUtils.decryptAesGcm(encryptedResponse, fastAuthKey)
            
            // 2. Validate Marker (Expecting 0x00 as per spec)
            if (decrypted.isNotEmpty() && decrypted[0] == 0x00.toByte()) {
                // 3. Atomic Update: Increment counter in DB
                val newCounter = record.core.transactionCounter + 1
                storageManager.updateTransactionCounter(record.core.keyID!!, newCounter)
                
                onLog("BLE Fast Tx: Success! Counter updated to $newCounter")
                true
            } else {
                onLog("BLE Fast Tx Error: Invalid Commit Marker")
                false
            }
        } catch (e: Exception) {
            onLog("BLE Fast Tx Error: Decryption failed (Unauthorized Vehicle)")
            false
        }
    }
}

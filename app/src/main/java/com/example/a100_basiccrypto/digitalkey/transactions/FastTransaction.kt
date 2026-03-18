package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.KeyState
import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_GET_STATUS
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_DESYNC
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_PERMISSION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_REPLAY_ATTACK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer

/**
 * Implementation of Fast Transaction (NFC Optimized).
 * Following the 3-Phase Security Model:
 * Phase 1: App receives and decrypts command, then responds with [INS + Counter].
 * Phase 2 & 3: Reader decrypts and validates the App's response.
 */
class FastTransaction(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    override fun processCommand(frame: LogicalFrame): ByteArray {
        // Expected Data: [moduleID (16b)] + [IV (12b)] + [Ciphertext (Counter + INS + Token...) + Tag]
        
        return try {
            val buffer = ByteBuffer.wrap(frame.payload)
            
            // 1. Identification
            if (buffer.remaining() < 16) return byteArrayOf(MSG_ERR_GENERAL, 0x01.toByte())
            val targetModuleID = ByteArray(16)
            buffer.get(targetModuleID)

            // 2. Query Active Key
            val allKeys = storageManager.getAllKeys()
            val record = allKeys.find { it.moduleID?.contentEquals(targetModuleID) == true }
                ?: return byteArrayOf(MSG_ERR_AUTH_FAIL, 0x02.toByte())

            if (record.keyState != KeyState.ACTIVE) {
                onLog("FastTx Blocked: Key is ${record.keyState}")
                return byteArrayOf(MSG_ERR_PERMISSION)
            }

            val fastAuthKey = record.fastAuthKey ?: return byteArrayOf(MSG_ERR_GENERAL, 0x03.toByte())

            // 3. Decrypt Payload
            val encryptedPart = ByteArray(buffer.remaining())
            buffer.get(encryptedPart)
            
            val decryptedData = CryptoUtils.decryptAesGcm(encryptedPart, fastAuthKey)
            val dataBuffer = ByteBuffer.wrap(decryptedData)

            // 4. Anti-Replay Validation
            if (dataBuffer.remaining() < 4) return byteArrayOf(MSG_ERR_GENERAL, 0x04.toByte())
            val receivedCounter = dataBuffer.int
            
            if (receivedCounter <= record.lastCounter) {
                onLog("FastTx Security: Replay Detected!")
                return byteArrayOf(MSG_ERR_REPLAY_ATTACK)
            }
            
            if (receivedCounter > record.lastCounter + 100) {
                onLog("FastTx Security: Desync Detected!")
                return byteArrayOf(MSG_ERR_DESYNC)
            }

            // 5. Business Validation (Phase 1 App side)
            val bizResult = when (frame.msgId) {
                INS_UNLOCK -> handleUnlock(record.friendlyName)
                INS_LOCK -> handleLock(record.friendlyName)
                INS_START_ENGINE -> handleStartEngine(dataBuffer, record.immobilizerToken)
                INS_STOP_ENGINE -> handleStopEngine(record.friendlyName)
                else -> MSG_ERR_GENERAL
            }

            if (bizResult == MSG_ERR_GENERAL || bizResult == MSG_ERR_AUTH_FAIL) {
                return byteArrayOf(bizResult)
            }

            // 6. Success: Update internal state
            storageManager.updateTransactionCounter(record.keyID!!, receivedCounter)
            onLog("FastTx Phase 1 OK: ${record.friendlyName}, INS=${"%02X".format(frame.msgId)}")

            // 7. Prepare Response for Reader (Phase 2 & 3 Support)
            // Payload: [INS (1b)] + [Counter (4b)] + [Status (1b)]
            val responsePayload = ByteBuffer.allocate(6).apply {
                put(frame.msgId)          // Return instruction code for Reader's Phase 3 check
                putInt(receivedCounter)    // Return Counter for Reader's Phase 2 check (Anti-Replay)
                put(MSG_GLOBAL_SUCCESS)    // Success status
            }.array()

            // Encrypt response with new IV
            CryptoUtils.encryptAesGcm(responsePayload, fastAuthKey)

        } catch (e: Exception) {
            Log.e("FastTransaction", "Security Failure: ${e.message}")
            onLog("FastTx: Authentication Failed (Tag Mismatch)")
            byteArrayOf(MSG_ERR_AUTH_FAIL)
        }
    }

    private fun handleUnlock(name: String): Byte {
        onLog("Vehicle [$name]: Unlock authorized")
        return MSG_GLOBAL_SUCCESS
    }

    private fun handleLock(name: String): Byte {
        onLog("Vehicle [$name]: Lock authorized")
        return MSG_GLOBAL_SUCCESS
    }

    private fun handleStopEngine(name: String): Byte {
        onLog("Vehicle [$name]: Stop engine authorized")
        return MSG_GLOBAL_SUCCESS
    }

    private fun handleStartEngine(buffer: ByteBuffer, expectedToken: ByteArray?): Byte {
        if (expectedToken == null || buffer.remaining() < 64) return MSG_ERR_GENERAL
        
        val receivedToken = ByteArray(64)
        buffer.get(receivedToken)
        
        return if (receivedToken.contentEquals(expectedToken)) {
            onLog("Engine Start authorized")
            MSG_GLOBAL_SUCCESS
        } else {
            onLog("Engine Start Denied: Token Mismatch")
            MSG_ERR_AUTH_FAIL
        }
    }

    override fun resetTransaction() {}
    override fun isTransactionComplete(): Boolean = true
}

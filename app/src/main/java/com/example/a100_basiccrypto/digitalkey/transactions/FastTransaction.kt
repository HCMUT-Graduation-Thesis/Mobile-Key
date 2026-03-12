package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.KeyState
import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_START_ENGINE
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
 * Implementation of Fast Transaction with Multi-key support.
 * Selects key by moduleID and validates ACTIVE state.
 */
class FastTransaction(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    override fun processCommand(frame: LogicalFrame): ByteArray {
        // Expected Data: [moduleID (16b)] + [IV (12b)] + [Ciphertext + Tag]
        
        return try {
            val buffer = ByteBuffer.wrap(frame.payload)
            
            // 1. Identify which vehicle is calling
            if (buffer.remaining() < 16) return byteArrayOf(MSG_ERR_GENERAL, 0x01.toByte())
            val targetModuleID = ByteArray(16)
            buffer.get(targetModuleID)

            // 2. Find matching ACTIVE key in storage
            val allKeys = storageManager.getAllKeys()
            val record = allKeys.find { it.moduleID?.contentEquals(targetModuleID) == true }
                ?: return byteArrayOf(MSG_ERR_AUTH_FAIL, 0x02.toByte()) // Module not recognized

            // Check if key is ACTIVE
            if (record.keyState != KeyState.ACTIVE) {
                onLog("FastTx Blocked: Key is in ${record.keyState} state.")
                return byteArrayOf(MSG_ERR_PERMISSION)
            }

            val fastAuthKey = record.fastAuthKey 
                ?: return byteArrayOf(MSG_ERR_GENERAL, 0x03.toByte())

            // 3. Decrypt remaining payload (IV is at current buffer position)
            val encryptedPart = ByteArray(buffer.remaining())
            buffer.get(encryptedPart)
            
            val decryptedData = CryptoUtils.decryptAesGcm(encryptedPart, fastAuthKey)
            val dataBuffer = ByteBuffer.wrap(decryptedData)

            // 4. Extract and Validate Counter (Anti-Replay)
            if (dataBuffer.remaining() < 4) return byteArrayOf(MSG_ERR_GENERAL, 0x04.toByte())
            val receivedCounter = dataBuffer.int
            
            if (receivedCounter <= record.lastCounter) {
                onLog("FastTx Error: Replay detected for Module ${record.friendlyName}")
                return byteArrayOf(MSG_ERR_REPLAY_ATTACK)
            }
            
            if (receivedCounter > record.lastCounter + 100) {
                onLog("FastTx Error: Desync for Module ${record.friendlyName}")
                return byteArrayOf(MSG_ERR_DESYNC)
            }

            // 5. Process Instruction (INS)
            val responseData = when (frame.msgId) {
                INS_UNLOCK -> handleUnlock(record.friendlyName)
                INS_LOCK -> handleLock(record.friendlyName)
                INS_START_ENGINE -> handleStartEngine(dataBuffer, record.immobilizerToken)
                INS_GET_STATUS -> handleGetStatus()
                else -> byteArrayOf(MSG_ERR_GENERAL, 0x05.toByte())
            }

            // 6. Update state on success
            if (responseData.isNotEmpty() && responseData[0] != MSG_ERR_GENERAL) {
                storageManager.updateTransactionCounter(record.keyID!!, receivedCounter)
                onLog("FastTx Success: ${record.friendlyName}, INS=${"%02X".format(frame.msgId)}")
            }

            // 7. Encrypt Response
            CryptoUtils.encryptAesGcm(responseData, fastAuthKey)

        } catch (e: Exception) {
            Log.e("FastTransaction", "Background processing failed: ${e.message}")
            onLog("FastTx Security Error: Tag mismatch or wrong key")
            byteArrayOf(MSG_ERR_AUTH_FAIL)
        }
    }

    private fun handleUnlock(name: String): ByteArray {
        onLog("Vehicle [$name]: Doors Unlocked")
        return byteArrayOf(MSG_GLOBAL_SUCCESS)
    }

    private fun handleLock(name: String): ByteArray {
        onLog("Vehicle [$name]: Doors Locked")
        return byteArrayOf(MSG_GLOBAL_SUCCESS)
    }

    private fun handleStartEngine(buffer: ByteBuffer, expectedToken: ByteArray?): ByteArray {
        if (expectedToken == null || buffer.remaining() < 64) return byteArrayOf(MSG_ERR_GENERAL)
        
        val receivedToken = ByteArray(64)
        buffer.get(receivedToken)
        
        return if (receivedToken.contentEquals(expectedToken)) {
            onLog("Engine Started Successfully")
            byteArrayOf(MSG_GLOBAL_SUCCESS)
        } else {
            onLog("Engine Start Denied: Invalid Token")
            byteArrayOf(MSG_ERR_AUTH_FAIL)
        }
    }

    private fun handleGetStatus(): ByteArray {
        return byteArrayOf(0x01.toByte())
    }

    override fun resetTransaction() {}
    override fun isTransactionComplete(): Boolean = true
}

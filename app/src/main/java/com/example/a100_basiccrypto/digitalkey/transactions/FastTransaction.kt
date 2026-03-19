package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_DESYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_PERMISSION
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_REPLAY_ATTACK
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer

/**
 * Implementation of Fast Transaction (NFC Optimized).
 */
class FastTransaction(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return try {
            val buffer = ByteBuffer.wrap(frame.payload)
            // Phase 1: Identification & Security Handshake
            // 1. Identification
            if (buffer.remaining() < 16) return byteArrayOf(MSG_ERR_GENERAL, 0x01.toByte())
            val targetModuleID = ByteArray(16)
            buffer.get(targetModuleID)

            // 2. Query Active Key
            val allKeys = storageManager.getAllKeys()
            val record = allKeys.find { it.core.moduleID?.contentEquals(targetModuleID) == true }
                ?: return byteArrayOf(MSG_ERR_AUTH_FAIL, 0x02.toByte())

            if (record.core.keyState != KeyState.ACTIVE) {
                onLog("FastTx Blocked: Key is ${record.core.keyState}")
                return byteArrayOf(MSG_ERR_PERMISSION)
            }

            val fastAuthKey = record.core.fastAuthKey ?: return byteArrayOf(MSG_ERR_GENERAL, 0x03.toByte())

            // 3. Decrypt Payload
            val encryptedPart = ByteArray(buffer.remaining())
            buffer.get(encryptedPart)
            
            val decryptedData = CryptoUtils.decryptAesGcm(encryptedPart, fastAuthKey)
            val dataBuffer = ByteBuffer.wrap(decryptedData)

            // 4. Anti-Replay Validation
            if (dataBuffer.remaining() < 4) return byteArrayOf(MSG_ERR_GENERAL, 0x04.toByte())
            val receivedCounter = dataBuffer.int
            
            // Use core.transactionCounter as the reference counter
            if (receivedCounter <= record.core.transactionCounter) {
                onLog("FastTx Security: Replay Detected!")
                return byteArrayOf(MSG_ERR_REPLAY_ATTACK)
            }
            
            if (receivedCounter > record.core.transactionCounter + 100) {
                onLog("FastTx Security: Desync Detected!")
                return byteArrayOf(MSG_ERR_DESYNC)
            }

            // 5. Business Validation
            val bizResult = when (frame.msgId) {
                INS_UNLOCK -> handleUnlock(record.friendlyName)
                INS_LOCK -> handleLock(record.friendlyName)
                INS_START_ENGINE -> handleStartEngine(dataBuffer, record.core.immobilizerToken)
                INS_STOP_ENGINE -> handleStopEngine(record.friendlyName)
                else -> MSG_ERR_GENERAL
            }

            if (bizResult == MSG_ERR_GENERAL || bizResult == MSG_ERR_AUTH_FAIL) {
                return byteArrayOf(bizResult)
            }

            // 6. Success: Update internal state
            storageManager.updateTransactionCounter(record.core.keyID!!, receivedCounter)
            onLog("FastTx Phase 1 OK: ${record.friendlyName}, INS=${"%02X".format(frame.msgId)}")

            // Phase 2: Decryption & Anti-Replay
            // 7. Prepare Response
            val responsePayload = ByteBuffer.allocate(6).apply {
                put(frame.msgId)
                putInt(receivedCounter)
                put(MSG_GLOBAL_SUCCESS)
            }.array()

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

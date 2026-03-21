package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.FAST_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_DESYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_PERMISSION
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import java.nio.ByteBuffer

/**
 * Implementation of Fast Transaction (Atomic Commit & 3-Way Handshake).
 */
class FastTransaction(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    // Staging Area (RAM only) - Keeps state between phases
    private var pendingRecord: DigitalKeyRecord? = null
    private var tempCounter: Int = 0
    private var isTransactionComplete = false

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return try {
            if (frame.msgId == FAST_COMMIT) {
                handleFinalCommit(frame)
            } else {
                handleActionRequest(frame)
            }
        } catch (e: Exception) {
            Log.e("FastTransaction", "Security Failure: ${e.message}")
            resetTransaction()
            byteArrayOf(MSG_ERR_AUTH_FAIL)
        }
    }

    /**
     * Phase 1 & 2: Action Request & Authorization Response
     */
    private fun handleActionRequest(frame: LogicalFrame): ByteArray {
        val buffer = ByteBuffer.wrap(frame.payload)
        
        // 1. Identification (Cleartext ModuleID per spec)
        if (buffer.remaining() < 16) {
            onLog("FastTx Error: ModuleID missing")
            return byteArrayOf(MSG_ERR_GENERAL, 0x01.toByte())
        }
        val targetModuleID = ByteArray(16)
        buffer.get(targetModuleID)

        // 2. Query Active Key
        val allKeys = storageManager.getAllKeys()
        val record = allKeys.find { it.core.moduleID?.contentEquals(targetModuleID) == true }
            ?: return byteArrayOf(MSG_ERR_AUTH_FAIL, 0x02.toByte())

        if (record.core.keyState != KeyState.ACTIVE) {
            onLog("FastTx Blocked: Key state is ${record.core.keyState}")
            return byteArrayOf(MSG_ERR_PERMISSION)
        }

        val fastAuthKey = record.core.fastAuthKey ?: return byteArrayOf(MSG_ERR_GENERAL, 0x03.toByte())

        // 3. Staging (RAM only): Calculate next counter but don't save to DB yet
        tempCounter = record.core.transactionCounter + 1
        pendingRecord = record
        isTransactionComplete = false

        // 4. Phase 2 Response (Encrypted)
        // Payload: [MSG_GLOBAL_SUCCESS] [TempCounter (4B)] + [Optional Token (64B)]
        val isEngineCmd = (frame.msgId == INS_START_ENGINE || frame.msgId == INS_STOP_ENGINE)
        val responseSize = 1 + 4 + (if (isEngineCmd) 64 else 0)
        
        val responsePlain = ByteBuffer.allocate(responseSize).apply {
            put(MSG_GLOBAL_SUCCESS)
            putInt(tempCounter)
            if (isEngineCmd) {
                put(record.core.immobilizerToken ?: ByteArray(64))
            }
        }.array()

        onLog("FastTx P2: Action=${"%02X".format(frame.msgId)}, TempCounter=$tempCounter")
        return CryptoUtils.encryptAesGcm(responsePlain, fastAuthKey)
    }

    /**
     * Phase 3: Final Commit
     */
    private fun handleFinalCommit(frame: LogicalFrame): ByteArray {
        val record = pendingRecord ?: run {
            onLog("FastTx Error: No pending transaction to commit")
            return byteArrayOf(MSG_ERR_GENERAL, 0x10.toByte())
        }

        val fastAuthKey = record.core.fastAuthKey ?: return byteArrayOf(MSG_ERR_GENERAL, 0x11.toByte())

        // 1. Decrypt and verify Phase 3 payload (Verifies the Reader has the key)
        try {
            CryptoUtils.decryptAesGcm(frame.payload, fastAuthKey)
        } catch (e: Exception) {
            onLog("FastTx P3: Commit verification failed (Tag mismatch)")
            resetTransaction()
            return byteArrayOf(MSG_ERR_AUTH_FAIL, 0x12.toByte())
        }

        // 2. FINAL COMMIT (Atomic): Write to persistent storage
        storageManager.updateTransactionCounter(record.core.keyID!!, tempCounter)
        
        isTransactionComplete = true
        onLog("FastTx P3: Atomic Commit Success. New Counter=$tempCounter")

        // 3. Response (Encrypted)
        val response = CryptoUtils.encryptAesGcm(byteArrayOf(MSG_GLOBAL_SUCCESS), fastAuthKey)
        
        // Clear pending state
        pendingRecord = null
        
        return response
    }

    override fun resetTransaction() {
        pendingRecord = null
        tempCounter = 0
        isTransactionComplete = false
    }

    override fun isTransactionComplete(): Boolean = isTransactionComplete
}

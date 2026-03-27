package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.FAST_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_PERMISSION
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import java.nio.ByteBuffer

/**
 * Implementation of Fast Transaction - Updated for IPassiveTransport.
 */
class FastTransaction(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    private var pendingRecord: DigitalKeyRecord? = null
    private var tempCounter: Int = 0
    private var isTransactionComplete = false

    override fun processCommand(frame: LogicalFrame, transport: IPassiveTransport): LogicalResponse {
        return try {
            if (frame.msgId == FAST_COMMIT) handleFinalCommit(frame)
            else handleActionRequest(frame)
        } catch (e: Exception) {
            Log.e("FastTransaction", "Security Failure: ${e.message}")
            resetTransaction()
            LogicalResponse(MSG_ERR_AUTH_FAIL)
        }
    }

    private fun handleActionRequest(frame: LogicalFrame): LogicalResponse {
        val buffer = ByteBuffer.wrap(frame.payload)
        
        if (buffer.remaining() < CryptoConstants.MODULE_ID_SIZE) {
            return LogicalResponse(MSG_ERR_GENERAL)
        }
        val targetModuleID = ByteArray(CryptoConstants.MODULE_ID_SIZE)
        buffer.get(targetModuleID)

        val allKeys = storageManager.getAllKeys()
        val record = allKeys.find { it.core.moduleID?.contentEquals(targetModuleID) == true }
            ?: return LogicalResponse(MSG_ERR_AUTH_FAIL)

        if (record.core.keyState != KeyState.ACTIVE) return LogicalResponse(MSG_ERR_PERMISSION)

        val fastAuthKey = record.core.fastAuthKey ?: return LogicalResponse(MSG_ERR_GENERAL)

        tempCounter = record.core.transactionCounter + 1
        pendingRecord = record
        isTransactionComplete = false

        val isEngineCmd = (frame.msgId == INS_START_ENGINE || frame.msgId == INS_STOP_ENGINE)
        val responseSize = 4 + (if (isEngineCmd) CryptoConstants.IMMOBILIZER_TOKEN_SIZE else 0)
        
        val responsePlain = ByteBuffer.allocate(responseSize).apply {
            putInt(tempCounter)
            if (isEngineCmd) put(record.core.immobilizerToken ?: ByteArray(64))
        }.array()

        onLog("FastTx P2: TempCounter=$tempCounter")
        val encrypted = CryptoUtils.encryptAesGcm(responsePlain, fastAuthKey)
        return LogicalResponse(MSG_GLOBAL_SUCCESS, encrypted)
    }

    private fun handleFinalCommit(frame: LogicalFrame): LogicalResponse {
        val record = pendingRecord ?: return LogicalResponse(MSG_ERR_GENERAL)
        val fastAuthKey = record.core.fastAuthKey ?: return LogicalResponse(MSG_ERR_GENERAL)

        try {
            CryptoUtils.decryptAesGcm(frame.payload, fastAuthKey)
        } catch (e: Exception) {
            resetTransaction()
            return LogicalResponse(MSG_ERR_AUTH_FAIL)
        }

        storageManager.updateTransactionCounter(record.core.keyID!!, tempCounter)
        isTransactionComplete = true
        onLog("FastTx P3: Atomic Commit Success.")

        val response = CryptoUtils.encryptAesGcm(byteArrayOf(MSG_GLOBAL_SUCCESS), fastAuthKey)
        pendingRecord = null
        return LogicalResponse(MSG_GLOBAL_SUCCESS, response)
    }

    override fun resetTransaction() {
        pendingRecord = null
        tempCounter = 0
        isTransactionComplete = false
    }

    override fun isTransactionComplete(): Boolean = isTransactionComplete
}

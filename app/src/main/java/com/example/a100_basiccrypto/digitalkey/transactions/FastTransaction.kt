package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
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
    private var isComplete = false

    override fun processCommand(frame: LogicalFrame, transport: IPassiveTransport): LogicalResponse {
        return try {
            if (frame.msgId == Fast.PHASE_COMMIT) handleFinalCommit(frame)
            else handleActionRequest(frame)
        } catch (e: Exception) {
            Log.e("FastTransaction", "Security Failure: ${e.message}")
            resetTransaction()
            LogicalResponse(Status.ERR_AUTH_FAIL)
        }
    }

    private fun handleActionRequest(frame: LogicalFrame): LogicalResponse {
        val buffer = ByteBuffer.wrap(frame.payload)
        
        if (buffer.remaining() < CryptoConstants.MODULE_ID_SIZE) {
            return LogicalResponse(Status.ERR_GENERAL)
        }
        val targetModuleID = ByteArray(CryptoConstants.MODULE_ID_SIZE)
        buffer.get(targetModuleID)

        val allKeys = storageManager.getAllKeys()
        val record = allKeys.find { it.moduleID?.contentEquals(targetModuleID) == true }
            ?: return LogicalResponse(Status.ERR_AUTH_FAIL)

        if (record.core.keyState != KeyState.ACTIVE) return LogicalResponse(Status.ERR_PERMISSION)

        val fastAuthKey = record.core.fastAuthKey ?: return LogicalResponse(Status.ERR_GENERAL)

        tempCounter = record.core.transactionCounter + 1
        pendingRecord = record
        isComplete = false

        val isEngineCmd = (frame.msgId == Fast.INS_START_ENGINE || frame.msgId == Fast.INS_STOP_ENGINE)

        val responseSize = 4 + (if (isEngineCmd) CryptoConstants.IMMOBILIZER_TOKEN_SIZE else 0)
        val responsePlain = ByteBuffer.allocate(responseSize).apply {
            putInt(tempCounter)
            if (isEngineCmd) put(record.immobilizerToken ?: ByteArray(64))
        }.array()

        onLog("FastTx P2: TempCounter=$tempCounter")
        

        val encrypted = CryptoUtils.encryptAesGcm(responsePlain, fastAuthKey)

        val keyID = record.core.keyID ?: ByteArray(CryptoConstants.KEY_ID_SIZE)
        val finalResponseData = ByteBuffer.allocate(keyID.size + encrypted.size).apply {
            put(keyID)
            put(encrypted)
        }.array()

        return LogicalResponse(Status.SUCCESS, finalResponseData)
    }

    private fun handleFinalCommit(frame: LogicalFrame): LogicalResponse {
        val record = pendingRecord ?: return LogicalResponse(Status.ERR_GENERAL)
        val fastAuthKey = record.core.fastAuthKey ?: return LogicalResponse(Status.ERR_GENERAL)

        try {
            CryptoUtils.decryptAesGcm(frame.payload, fastAuthKey)
        } catch (e: Exception) {
            resetTransaction()
            return LogicalResponse(Status.ERR_AUTH_FAIL)
        }

        storageManager.updateTransactionCounter(record.core.keyID!!, tempCounter)
        isComplete = true
        onLog("FastTx P3: Atomic Commit Success.")

        val response = CryptoUtils.encryptAesGcm(byteArrayOf(Status.SUCCESS), fastAuthKey)
        pendingRecord = null
        return LogicalResponse(Status.SUCCESS, response)
    }

    override fun resetTransaction() {
        pendingRecord = null
        tempCounter = 0
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete
}

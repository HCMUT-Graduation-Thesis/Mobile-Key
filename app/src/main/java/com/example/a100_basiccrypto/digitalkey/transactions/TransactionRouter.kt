package com.example.a100_basiccrypto.digitalkey.transactions

import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_TELEMETRY
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_INVALID_CLASS
import com.example.a100_basiccrypto.digitalkey.core.TransportPolicyManager
import com.example.a100_basiccrypto.digitalkey.core.TransportType

/**
 * Central router for all digital key transactions.
 * Neutral to transport (NFC/BLE).
 */
class TransactionRouter(
    private val pairingHandler: ITransactionHandler,
    private val fastHandler: ITransactionHandler? = null,
    private val standardHandler: ITransactionHandler? = null
) {

    /**
     * Routes a logical frame to the correct executor.
     */
    fun route(frame: LogicalFrame, transport: TransportType): LogicalFrame {
        // 1. Check Dev Config Policy
        if (!TransportPolicyManager.isTransportAllowed(frame.msgClass, transport)) {
            return LogicalFrame(frame.msgClass, frame.msgId, byteArrayOf(MSG_ERR_GENERAL, 0x09.toByte()))
        }

        // 2. Route based on Class
        val responsePayload = when (frame.msgClass) {
            CLASS_OWNER_PAIRING, 0x80.toByte() -> pairingHandler.processCommand(frame)
            
            CLASS_FAST_ACTION, CLASS_ENGINE_OP, CLASS_TELEMETRY -> {
                fastHandler?.processCommand(frame) ?: byteArrayOf(MSG_ERR_GENERAL, 0x01.toByte())
            }
            
            CLASS_FRIEND_PAIRING -> {
                // Future: friendPairingHandler.processCommand(frame)
                byteArrayOf(MSG_ERR_GENERAL, 0x03.toByte())
            }
            
            CLASS_ADMIN -> {
                standardHandler?.processCommand(frame) ?: byteArrayOf(MSG_ERR_GENERAL, 0x02.toByte())
            }
            
            else -> byteArrayOf(MSG_ERR_INVALID_CLASS)
        }

        return LogicalFrame(frame.msgClass, frame.msgId, responsePayload)
    }
    
    fun resetAll() {
        pairingHandler.resetTransaction()
        fastHandler?.resetTransaction()
        standardHandler?.resetTransaction()
    }
}

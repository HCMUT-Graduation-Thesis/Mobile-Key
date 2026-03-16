package com.example.a100_basiccrypto.digitalkey.transactions

import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_TELEMETRY
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_INVALID_CLASS
import com.example.a100_basiccrypto.digitalkey.core.TransportPolicyManager
import com.example.a100_basiccrypto.digitalkey.core.TransportType

/**
 * Central router for all digital key transactions.
 * Routes CLASS_ADMIN (0x40) to StandardTransaction.
 */
class TransactionRouter(
    private val pairingHandler: ITransactionHandler,
    private val fastHandler: ITransactionHandler? = null,
    private val standardHandler: ITransactionHandler? = null
) {

    fun route(frame: LogicalFrame, transport: TransportType): LogicalFrame {
        if (!TransportPolicyManager.isTransportAllowed(frame.msgClass, transport)) {
            return LogicalFrame(frame.msgClass, frame.msgId, byteArrayOf(MSG_ERR_GENERAL))
        }

        val responsePayload = when (frame.msgClass) {
            CLASS_OWNER_PAIRING, 0x80.toByte() -> pairingHandler.processCommand(frame)
            
            CLASS_FAST_ACTION, CLASS_ENGINE_OP, CLASS_TELEMETRY -> {
                fastHandler?.processCommand(frame) ?: byteArrayOf(MSG_ERR_GENERAL)
            }
            
            CLASS_ADMIN -> {
                standardHandler?.processCommand(frame) ?: byteArrayOf(MSG_ERR_GENERAL)
            }
            
            CLASS_FRIEND_PAIRING -> {
                byteArrayOf(MSG_ERR_GENERAL)
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

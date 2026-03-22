package com.example.a100_basiccrypto.shared.link

import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_TELEMETRY
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_INVALID_CLASS
import com.example.a100_basiccrypto.shared.policy.TransportPolicyManager
import com.example.a100_basiccrypto.shared.policy.TransportType

/**
 * Central router for all digital key transactions.
 * Orchestrates commands between physical transport and logic handlers.
 */
class TransactionRouter(
    private val pairingHandler: ITransactionHandler,
    private val fastHandler: ITransactionHandler? = null,
    private val standardHandler: ITransactionHandler? = null,
    private val friendPairingHandler: ITransactionHandler? = null
) {

    /**
     * Routes an incoming frame to the appropriate handler based on its class.
     */
    fun route(frame: LogicalFrame, transport: TransportType): LogicalFrame {
        // Enforce transport policy
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
                friendPairingHandler?.processCommand(frame) ?: byteArrayOf(MSG_ERR_GENERAL)
            }
            
            else -> byteArrayOf(MSG_ERR_INVALID_CLASS)
        }

        return LogicalFrame(frame.msgClass, frame.msgId, responsePayload)
    }
    
    /**
     * Resets all internal handlers to clear session states.
     */
    fun resetAll() {
        pairingHandler.resetTransaction()
        fastHandler?.resetTransaction()
        standardHandler?.resetTransaction()
        friendPairingHandler?.resetTransaction()
    }
}

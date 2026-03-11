package com.example.a100_basiccrypto.digitalkey.transactions

import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_GENERAL

class TransactionRouter(
    private val pairingHandler: ITransactionHandler
    // Future: private val standardHandler: ITransactionHandler,
    // Future: private val fastHandler: ITransactionHandler
) {

    fun route(msgId: Byte, payload: ByteArray): ByteArray {
        val idInt = msgId.toInt() and 0xFF

        return when (idInt) {
            in 0x10..0x2F -> pairingHandler.processCommand(msgId, payload)
            
            in 0x30..0x4F -> {
                // Future: standardHandler.processCommand(msgId, payload)
                byteArrayOf(MSG_ERR_GENERAL, 0x00.toByte())
            }
            
            in 0x50..0x6F -> {
                // Future: fastHandler.processCommand(msgId, payload)
                byteArrayOf(MSG_ERR_GENERAL, 0x00.toByte())
            }
            
            else -> byteArrayOf(MSG_ERR_GENERAL, 0x01.toByte())
        }
    }
    
    fun resetAll() {
        pairingHandler.resetTransaction()
    }
}

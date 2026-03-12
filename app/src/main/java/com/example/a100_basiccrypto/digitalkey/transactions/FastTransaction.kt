package com.example.a100_basiccrypto.digitalkey.transactions

import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_GET_STATUS
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager

class FastTransaction(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return when (frame.msgId) {
            INS_UNLOCK -> {
                onLog("Fast Action: Unlocking Vehicle...")
                byteArrayOf(MSG_GLOBAL_SUCCESS)
            }
            INS_LOCK -> {
                onLog("Fast Action: Locking Vehicle...")
                byteArrayOf(MSG_GLOBAL_SUCCESS)
            }
            INS_START_ENGINE -> {
                onLog("Fast Action: Validating Token & Starting Engine...")
                byteArrayOf(MSG_GLOBAL_SUCCESS)
            }
            INS_GET_STATUS -> {
                onLog("Fast Action: Returning Vehicle Status...")
                byteArrayOf(0x01.toByte())
            }
            else -> byteArrayOf(0xE0.toByte())
        }
    }

    override fun resetTransaction() {}
    override fun isTransactionComplete(): Boolean = true
}

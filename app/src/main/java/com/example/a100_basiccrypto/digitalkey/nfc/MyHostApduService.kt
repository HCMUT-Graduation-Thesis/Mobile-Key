package com.example.a100_basiccrypto.digitalkey.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.TransactionRouter
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_TELEMETRY
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.FINAL_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.policy.TransportType
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.shared.physical.NfcConstants.CLA_ISO
import com.example.a100_basiccrypto.shared.physical.NfcConstants.CLA_PROPRIETARY
import com.example.a100_basiccrypto.shared.physical.NfcConstants.INS_GET_NEXT_CHUNK
import com.example.a100_basiccrypto.shared.physical.NfcConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.shared.physical.NfcConstants.TRANSACTION_TIMEOUT_MS
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.OwnerPairingTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.StandardTransaction

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcDigitalKey"
        const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
        const val ACTION_NFC_RESULT = "com.example.a100_basiccrypto.NFC_RESULT"
        
        @Volatile
        var isPairingModeEnabled: Boolean = false

        @Volatile
        var friendPairingHandler: ITransactionHandler? = null
    }

    private val chainingManager = NfcChainingManager()
    private val storageManager by lazy { SecureKeyStorageManager(applicationContext) }
    private val identityCrypto = DilithiumIdentityCryptoImpl()
    
    private val router: TransactionRouter by lazy {
        val pairingHandler = OwnerPairingTransaction(
            identityCrypto = identityCrypto,
            storageManager = storageManager,
            passwordProvider = { PasswordManager.getPassword(applicationContext) },
            onLog = { sendLogToGui(it) }
        )
        val fastHandler = FastTransaction(
            storageManager = storageManager,
            onLog = { sendLogToGui(it) }
        )
        val standardHandler = StandardTransaction(
            identityCrypto = identityCrypto,
            storageManager = storageManager,
            passwordProvider = { PasswordManager.getPassword(applicationContext) },
            onLog = { sendLogToGui(it) }
        )
        TransactionRouter(
            pairingHandler = pairingHandler,
            fastHandler = fastHandler,
            standardHandler = standardHandler,
            friendPairingHandler = null
        )
    }

    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val timeoutRunnable = Runnable { handleTimeout() }

    private fun sendLogToGui(message: String) {
        val intent = Intent(LOG_ACTION).apply {
            putExtra("log_message", message)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun broadcastResultToActivity(actionName: String, isSuccess: Boolean) {
        val intent = Intent(ACTION_NFC_RESULT).apply {
            putExtra("action_name", actionName)
            putExtra("is_success", isSuccess)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (commandApdu == null || commandApdu.size < 2) return SW_INTERNAL_ERROR

        Log.d(TAG, "RX: ${toHexString(commandApdu)}")

        val cla = commandApdu[0]
        val ins = commandApdu[1]
        
        if (cla == CLASS_OWNER_PAIRING || cla == 0x80.toByte()) {
            if (!isPairingModeEnabled) {
                Log.w(TAG, "Pairing Blocked: Mode not enabled by User.")
                val resp = SW_UNKNOWN_CMD
                Log.d(TAG, "TX: ${toHexString(resp)}")
                return resp
            }
        }

        if (cla == CLASS_FRIEND_PAIRING) {
            if (friendPairingHandler == null) {
                val resp = SW_UNKNOWN_CMD
                Log.d(TAG, "TX: ${toHexString(resp)}")
                return resp
            }
        }

        if (cla == CLA_ISO && ins == 0xA4.toByte()) {
            resetSession()
            sendLogToGui("System: Reader Connected.")
            val resp = SW_SUCCESS
            Log.d(TAG, "TX: ${toHexString(resp)}")
            return resp
        }

        if (ins == INS_GET_NEXT_CHUNK) {
            val chunkIndex = if (commandApdu.size >= 3) commandApdu[2].toInt() and 0xFF else 0
            val resp = chainingManager.getNextOutgoingChunk(chunkIndex)
            Log.d(TAG, "TX (chunk): ${toHexString(resp)}")
            return resp
        }

        val isAllowedClass = cla == CLA_ISO || 
                            cla == CLA_PROPRIETARY || 
                            cla == CLASS_OWNER_PAIRING || 
                            cla == CLASS_FAST_ACTION || 
                            cla == CLASS_ENGINE_OP || 
                            cla == CLASS_TELEMETRY || 
                            cla == CLASS_ADMIN || 
                            cla == CLASS_FRIEND_PAIRING ||
                            cla == 0x80.toByte()

        if (!isAllowedClass) {
            val resp = SW_UNKNOWN_CMD
            Log.d(TAG, "TX: ${toHexString(resp)}")
            return resp
        }
        
        resetTimeoutTimer()

        val fullPayload = chainingManager.handleIncomingFragment(commandApdu)
        
        val response = if (fullPayload != null) {
            val inputFrame = LogicalFrame(cla, ins, fullPayload)
            
            val logicalResponse = if (cla == CLASS_FRIEND_PAIRING) {
                friendPairingHandler?.processCommand(inputFrame) ?: LogicalResponse(MSG_ERR_GENERAL)
            } else {
                router.route(inputFrame, TransportType.NFC)
            }
            
            val result = logicalResponse.serialize()
            
            // Handle NFC Result Broadcasts
            handleActionBroadcasts(cla, ins, logicalResponse)

            if (result.size > MAX_APDU_PAYLOAD_SIZE) {
                chainingManager.setOutgoingBuffer(result)
                chainingManager.getNextOutgoingChunk(0)
            } else {
                // If it's already a full APDU response (2 bytes error code), send as is
                if (result.size == 2 && (result[0].toInt() and 0xFF) >= 0x60) {
                    result
                } else {
                    // For LogicalResponse, serialize it and append SW_SUCCESS for NFC
                    result + SW_SUCCESS
                }
            }
        } else {
            SW_HAS_MORE_DATA
        }

        Log.d(TAG, "TX: ${toHexString(response)}")
        return response
    }

    private fun handleActionBroadcasts(cla: Byte, ins: Byte, response: LogicalResponse) {
        val actionName = when {
            cla == CLASS_FAST_ACTION && ins == INS_UNLOCK -> "UNLOCK"
            cla == CLASS_FAST_ACTION && ins == INS_LOCK -> "LOCK"
            cla == CLASS_ENGINE_OP && ins == INS_START_ENGINE -> "START ENGINE"
            cla == CLASS_ENGINE_OP && ins == INS_STOP_ENGINE -> "STOP ENGINE"
            cla == CLASS_ADMIN && ins == FINAL_COMMIT -> "RECOVERY & ACTION"
            cla == CLASS_FRIEND_PAIRING && ins == 0x17.toByte() -> "FRIEND PAIRING"
            else -> null
        }

        if (actionName != null) {
            val isSuccess = response.status == MSG_GLOBAL_SUCCESS
            broadcastResultToActivity(actionName, isSuccess)
        }
    }

    private fun toHexString(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02X".format(it) }
    }

    private fun resetSession() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
        chainingManager.clear()
        router.resetAll()
    }

    private fun resetTimeoutTimer() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
    }

    private fun handleTimeout() {
        chainingManager.clear()
        router.resetAll()
        friendPairingHandler = null
        sendLogToGui("Session Timeout")
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        chainingManager.clear()
    }
}

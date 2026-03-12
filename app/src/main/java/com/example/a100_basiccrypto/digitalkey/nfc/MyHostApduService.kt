package com.example.a100_basiccrypto.digitalkey.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_TELEMETRY
import com.example.a100_basiccrypto.digitalkey.core.TransportType
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.CLA_ISO
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.CLA_PROPRIETARY
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.INS_GET_NEXT_CHUNK
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.TRANSACTION_TIMEOUT_MS
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.OwnerPairingTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.TransactionRouter

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcDigitalKey"
        const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
        
        // Gatekeeper flag for Pairing
        @Volatile
        var isPairingModeEnabled: Boolean = false
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
        TransactionRouter(
            pairingHandler = pairingHandler,
            fastHandler = fastHandler
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

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (commandApdu == null || commandApdu.size < 2) return SW_INTERNAL_ERROR

        val cla = commandApdu[0]
        val ins = commandApdu[1]
        
        // 1. Security Check: Only allow Pairing commands if explicitly enabled by UI
        if (cla == CLASS_OWNER_PAIRING || cla == 0x80.toByte()) {
            if (!isPairingModeEnabled) {
                Log.w(TAG, "Pairing Blocked: Mode not enabled by User.")
                return SW_UNKNOWN_CMD 
            }
        }

        // 2. Handle SELECT AID
        if (cla == CLA_ISO && ins == 0xA4.toByte()) {
            resetSession()
            sendLogToGui("System: Reader Connected.")
            return SW_SUCCESS
        }

        // 3. Handle GET_NEXT_CHUNK
        // Now using 0xFF, so it will NEVER collide with business INS codes (0x01, 0x02, etc.)
        if (ins == INS_GET_NEXT_CHUNK) {
            val chunkIndex = if (commandApdu.size >= 3) commandApdu[2].toInt() and 0xFF else 0
            return chainingManager.getNextOutgoingChunk(chunkIndex)
        }

        // 4. Validate supported classes
        val isAllowedClass = cla == CLA_ISO || 
                            cla == CLA_PROPRIETARY || 
                            cla == CLASS_OWNER_PAIRING || 
                            cla == CLASS_FAST_ACTION || 
                            cla == CLASS_ENGINE_OP || 
                            cla == CLASS_TELEMETRY || 
                            cla == CLASS_ADMIN || 
                            cla == CLASS_FRIEND_PAIRING ||
                            cla == 0x80.toByte()

        if (!isAllowedClass) return SW_UNKNOWN_CMD
        
        resetTimeoutTimer()

        val fullPayload = chainingManager.handleIncomingFragment(commandApdu)
        
        return if (fullPayload != null) {
            val inputFrame = LogicalFrame(cla, ins, fullPayload)
            val responseFrame = router.route(inputFrame, TransportType.NFC)
            val result = responseFrame.payload
            
            if (result.size > MAX_APDU_PAYLOAD_SIZE) {
                chainingManager.setOutgoingBuffer(result)
                chainingManager.getNextOutgoingChunk(0)
            } else {
                if (result.size == 2 && (result[0].toInt() and 0xFF) >= 0x60) {
                    result
                } else {
                    result + SW_SUCCESS
                }
            }
        } else {
            SW_HAS_MORE_DATA
        }
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
        sendLogToGui("Session Timeout")
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        chainingManager.clear()
    }
}

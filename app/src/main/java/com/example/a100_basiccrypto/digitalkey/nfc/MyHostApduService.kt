package com.example.a100_basiccrypto.digitalkey.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.CLA_ISO
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.CLA_PROPRIETARY
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.INS_GET_NEXT_CHUNK
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.TRANSACTION_TIMEOUT_MS
import com.example.a100_basiccrypto.digitalkey.storage.SharedPreferencesKeyStorage
import com.example.a100_basiccrypto.digitalkey.transactions.ITransactionHandler
import com.example.a100_basiccrypto.digitalkey.transactions.OwnerPairingTransaction

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcDigitalKey"
        const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
    }

    private val chainingManager = NfcChainingManager()
    private val storageManager by lazy { SharedPreferencesKeyStorage(applicationContext) }
    private val identityCrypto = DilithiumIdentityCryptoImpl()
    
    // In a real app, this would be a list of handlers selected by state/command
    private val pairingHandler: ITransactionHandler by lazy {
        OwnerPairingTransaction(
            identityCrypto = identityCrypto,
            storageManager = storageManager,
            passwordProvider = { "12345678" }, // Hardcoded for now
            onLog = { sendLogToGui(it) }
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
        if (commandApdu == null) return SW_INTERNAL_ERROR

        val hexCommand = commandApdu.toHex()
        Log.d(TAG, "RX: ${if (hexCommand.length > 40) hexCommand.take(40) + "..." else hexCommand}")

        // Phase 1: AID Selection (ISO Standard)
        if (commandApdu.size >= 2 && commandApdu[0] == CLA_ISO && commandApdu[1] == 0xA4.toByte()) {
            resetSession()
            sendLogToGui("Phase 1: Connected. Starting timeout...")
            return SW_SUCCESS
        }

        if (commandApdu[0] != CLA_PROPRIETARY) return SW_UNKNOWN_CMD
        
        resetTimeoutTimer()

        // Handle GET_NEXT_CHUNK (TX Chaining)
        if (commandApdu[1] == INS_GET_NEXT_CHUNK) {
            val chunkIndex = commandApdu[2].toInt() and 0xFF
            return chainingManager.getNextOutgoingChunk(chunkIndex)
        }

        // Handle Fragmentation (RX Chaining)
        val fullPayload = chainingManager.handleIncomingFragment(commandApdu)
        
        return if (fullPayload != null) {
            // Full payload received, route to handler
            val result = pairingHandler.processCommand(fullPayload)
            
            // Check if result needs Chaining (TX)
            if (result.size > ApduConstants.MAX_APDU_PAYLOAD_SIZE) {
                chainingManager.setOutgoingBuffer(result)
                chainingManager.getNextOutgoingChunk(0)
            } else {
                result
            }
        } else {
            // Need more chunks
            ApduConstants.SW_HAS_MORE_DATA
        }
    }

    private fun resetSession() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
        chainingManager.clear()
        pairingHandler.resetTransaction()
    }

    private fun resetTimeoutTimer() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
    }

    private fun handleTimeout() {
        chainingManager.clear()
        pairingHandler.resetTransaction()
        sendLogToGui("Transaction Timeout")
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        chainingManager.clear()
    }
}

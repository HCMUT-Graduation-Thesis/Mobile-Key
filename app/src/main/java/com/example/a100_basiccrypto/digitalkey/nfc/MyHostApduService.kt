package com.example.a100_basiccrypto.digitalkey.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.AID_HCE
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.CLA_ISO
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.CLA_PROPRIETARY
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.INS_GET_NEXT_CHUNK
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.TRANSACTION_TIMEOUT_MS
import com.example.a100_basiccrypto.digitalkey.storage.SharedPreferencesKeyStorage
import com.example.a100_basiccrypto.digitalkey.transactions.OwnerPairingTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.TransactionRouter

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcDigitalKey"
        const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
    }

    private val chainingManager = NfcChainingManager()
    private val storageManager by lazy { SharedPreferencesKeyStorage(applicationContext) }
    private val identityCrypto = DilithiumIdentityCryptoImpl()
    
    private val router: TransactionRouter by lazy {
        val pairingHandler = OwnerPairingTransaction(
            identityCrypto = identityCrypto,
            storageManager = storageManager,
            passwordProvider = { "12345678" }, // Hardcoded for now
            onLog = { sendLogToGui(it) }
        )
        TransactionRouter(pairingHandler)
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
        val cla = commandApdu[0]
        val ins = commandApdu[1]
        
        Log.d(TAG, "RX: CLA=${"%02X".format(cla)}, INS=${"%02X".format(ins)}, Full=${if (hexCommand.length > 30) hexCommand.take(30) + "..." else hexCommand}")

        // 1. SELECT AID
        if (commandApdu.size >= 2 && cla == CLA_ISO && ins == 0xA4.toByte()) {
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

        // Lấy INS làm msgId
        val msgId = commandApdu[1]

        // Handle Fragmentation (RX Chaining)
        val fullPayload = chainingManager.handleIncomingFragment(commandApdu)
        
        return if (fullPayload != null) {
            Log.d(TAG, "Routing: msgId=${"%02X".format(ins)}, Payload size=${fullPayload.size}")
            val result = router.route(ins, fullPayload)
            
            Log.d(TAG, "Response: size=${result.size}, Data=${result.toHex().take(70)}...")

            if (result.size > MAX_APDU_PAYLOAD_SIZE) {
                chainingManager.setOutgoingBuffer(result)
                chainingManager.getNextOutgoingChunk(0)
            } else {
                result
            }
        } else {
            Log.d(TAG, "Chaining: Waiting for more chunks...")
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
        sendLogToGui("Transaction Timeout")
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        chainingManager.clear()
    }
}

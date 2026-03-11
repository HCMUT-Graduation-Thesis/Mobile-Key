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
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.OwnerPairingTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.TransactionRouter

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcDigitalKey"
        const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
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
        if (commandApdu == null || commandApdu.size < 2) return SW_INTERNAL_ERROR

        val hexCommand = commandApdu.toHex()
        val cla = commandApdu[0]
        val ins = commandApdu[1]
        
        val claHex = "%02X".format(cla)
        val insHex = "%02X".format(ins)
        val p1Hex = if (commandApdu.size > 2) "%02X".format(commandApdu[2]) else "--"
        val p2Hex = if (commandApdu.size > 3) "%02X".format(commandApdu[3]) else "--"
        
        Log.d(TAG, "RX: CLA=$claHex, INS=$insHex, P1=$p1Hex, P2=$p2Hex, Full=$hexCommand")

        if (commandApdu.size >= 2 && cla == CLA_ISO && ins == 0xA4.toByte()) {
            resetSession()
            sendLogToGui("Phase 1: Connected.")
            return SW_SUCCESS
        }

        if (cla != CLA_ISO && cla != CLA_PROPRIETARY) return SW_UNKNOWN_CMD
        
        resetTimeoutTimer()

        if (ins == INS_GET_NEXT_CHUNK && commandApdu.size >= 3) {
            val chunkIndex = commandApdu[2].toInt() and 0xFF
            val chunk = chainingManager.getNextOutgoingChunk(chunkIndex)
            Log.d(TAG, "TX Chunk #$chunkIndex: ${chunk.toHex()}")
            return chunk
        }

        val fullPayload = chainingManager.handleIncomingFragment(commandApdu)
        
        return if (fullPayload != null) {
            val dataPayload = if (fullPayload === commandApdu) {
                if (commandApdu.size >= 5) {
                    val lc = commandApdu[4].toInt() and 0xFF
                    commandApdu.sliceArray(5 until minOf(commandApdu.size, 5 + lc))
                } else ByteArray(0)
            } else {
                fullPayload
            }

            Log.d(TAG, "Routing: msgId=${"%02X".format(ins)}, Data size=${dataPayload.size}")
            val result = router.route(ins, dataPayload)
            
            Log.d(TAG, "TX Full Response: ${result.toHex()}")

            if (result.size > MAX_APDU_PAYLOAD_SIZE) {
                chainingManager.setOutgoingBuffer(result)
                val firstChunk = chainingManager.getNextOutgoingChunk(0)
                Log.d(TAG, "TX Chunk #0: ${firstChunk.toHex()}")
                firstChunk
            } else {
                result
            }
        } else {
            Log.d(TAG, "Chaining: Waiting for more fragments...")
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

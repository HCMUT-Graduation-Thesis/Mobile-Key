package com.example.a100_basiccrypto

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.ApduConstants.CLA_ISO
import com.example.a100_basiccrypto.ApduConstants.CLA_PROPRIETARY
import com.example.a100_basiccrypto.ApduConstants.INS_COMMIT_PAIRING
import com.example.a100_basiccrypto.ApduConstants.INS_EXCHANGE_AND_DERIVE
import com.example.a100_basiccrypto.ApduConstants.INS_EXCHANGE_IMMOBILIZER
import com.example.a100_basiccrypto.ApduConstants.INS_GET_NEXT_CHUNK
import com.example.a100_basiccrypto.ApduConstants.INS_VERIFY_NONCE
import com.example.a100_basiccrypto.ApduConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.ApduConstants.SW_DATA_MISMATCH
import com.example.a100_basiccrypto.ApduConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.ApduConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.ApduConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.ApduConstants.SW_SUCCESS
import com.example.a100_basiccrypto.ApduConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.ApduConstants.TRANSACTION_TIMEOUT_MS
import com.example.a100_basiccrypto.CryptoUtils.hexToBytes
import com.example.a100_basiccrypto.CryptoUtils.toHex
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcEcdhLock"
        private const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
        private const val HKDF_INFO = "NFC_OWNER_CONFIRM"
    }

    private var currentSessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private val identityCrypto: IIdentityCrypto = DilithiumIdentityCryptoImpl()
    
    // Chaining Buffers
    private var rxBuffer: ByteArrayOutputStream? = null
    private var txBuffer: ByteArray? = null
    
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

        // AID Selection
        if (commandApdu.size >= 2 && commandApdu[0] == CLA_ISO && commandApdu[1] == 0xA4.toByte()) {
            startTransaction()
            sendLogToGui("Phase 1: Connected to Reader")
            return SW_SUCCESS
        }

        if (commandApdu[0] != CLA_PROPRIETARY) return SW_UNKNOWN_CMD
        resetTimeout()

        return when (commandApdu[1]) {
            INS_EXCHANGE_AND_DERIVE -> handlePhase2a(commandApdu)
            INS_VERIFY_NONCE -> handlePhase2b(commandApdu)
            INS_EXCHANGE_IMMOBILIZER -> handlePhase3Rx(commandApdu)
            INS_GET_NEXT_CHUNK -> handlePhase3Tx(commandApdu)
            INS_COMMIT_PAIRING -> handlePhase4(commandApdu)
            else -> SW_UNKNOWN_CMD
        }
    }

    private fun startTransaction() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
        currentSessionKey = null
        rxBuffer = null
        txBuffer = null
    }

    private fun resetTimeout() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
    }

    private fun handleTimeout() {
        resetBuffers()
        sendLogToGui("Transaction Failed (Timeout)")
    }

    private fun resetBuffers() {
        currentSessionKey = null
        rxBuffer = null
        txBuffer = null
    }

    /**
     * Phase 2.a: Ephemeral Key Exchange
     */
    private fun handlePhase2a(apdu: ByteArray): ByteArray {
        return try {
            val pubKeyReader = CryptoUtils.getPublicKeyFromHex(apdu.sliceArray(5 until 5 + 65).toHex())
            val kpg = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            ephemeralKeyPair = kpg.generateKeyPair()
            val sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, pubKeyReader)
            val salt = PasswordManager.getPassword(this).toByteArray()
            currentSessionKey = CryptoUtils.deriveSessionKey(sharedSecret, salt, HKDF_INFO.toByteArray(), 32)
            
            sendLogToGui("Phase 2.a: Session Key generated")
            val ecPubKey = ephemeralKeyPair!!.public as java.security.interfaces.ECPublicKey
            byteArrayOf(0x04.toByte()) + ecPubKey.w.affineX.toByteArray().normalize(32) + ecPubKey.w.affineY.toByteArray().normalize(32) + SW_SUCCESS
        } catch (e: Exception) { SW_INTERNAL_ERROR }
    }

    /**
     * Phase 2.b: Nonce Verification
     */
    private fun handlePhase2b(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedNonce = CryptoUtils.decryptAesGcm(apdu.sliceArray(5 until apdu.size), sessionKey)
            sendLogToGui("Phase 2.b: Nonce verified")
            CryptoUtils.encryptAesGcm(decryptedNonce, sessionKey) + SW_SUCCESS
        } catch (e: Exception) { SW_DECRYPTION_FAILED }
    }

    /**
     * Phase 3 (RX): Receive Dilithium PK & Token via Chaining
     */
    private fun handlePhase3Rx(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        val chunkIndex = apdu[2].toInt() and 0xFF
        val isLastChunk = apdu[3].toInt() == 0x01
        
        if (chunkIndex == 0) rxBuffer = ByteArrayOutputStream()
        
        val lc = apdu[4].toInt() and 0xFF
        rxBuffer?.write(apdu, 5, lc)
        
        if (!isLastChunk) {
            sendLogToGui("Phase 3: Receiving Chunk #$chunkIndex")
            return SW_HAS_MORE_DATA
        }
        
        // Last chunk received, process full buffer
        return try {
            val fullCiphertext = rxBuffer?.toByteArray() ?: return SW_INTERNAL_ERROR
            val decryptedData = CryptoUtils.decryptAesGcm(fullCiphertext, sessionKey)
            
            val token = decryptedData.sliceArray(decryptedData.size - 64 until decryptedData.size).toHex()
            val longPkReader = decryptedData.sliceArray(0 until decryptedData.size - 64).toHex()
            
            getSharedPreferences("nfc_lock_prefs", MODE_PRIVATE).edit()
                .putString("last_reader_dilithium_pk", longPkReader)
                .putString("immobilizer_token", token).apply()
                
            sendLogToGui("Phase 3: Data Received. Preparing response...")
            
            // Prepare response (Long PK HCE) for Chaining TX
            val longPkHce = identityCrypto.getPublicKey()
            txBuffer = CryptoUtils.encryptAesGcm(longPkHce, sessionKey)
            
            // Send first chunk of response
            sendNextChunk(0)
        } catch (e: Exception) { SW_DECRYPTION_FAILED }
    }

    /**
     * Phase 3 (TX): Reader pulls response chunks
     */
    private fun handlePhase3Tx(apdu: ByteArray): ByteArray {
        val chunkIndex = apdu[2].toInt() and 0xFF
        return sendNextChunk(chunkIndex)
    }

    private fun sendNextChunk(chunkIndex: Int): ByteArray {
        val buffer = txBuffer ?: return SW_INTERNAL_ERROR
        val offset = chunkIndex * MAX_APDU_PAYLOAD_SIZE
        
        if (offset >= buffer.size) return SW_INTERNAL_ERROR
        
        val remaining = buffer.size - offset
        val chunkSize = minOf(remaining, MAX_APDU_PAYLOAD_SIZE)
        val chunk = buffer.sliceArray(offset until offset + chunkSize)
        
        return if (offset + chunkSize < buffer.size) {
            sendLogToGui("Phase 3: Sending Chunk #$chunkIndex")
            chunk + SW_HAS_MORE_DATA
        } else {
            sendLogToGui("Phase 3: Final Chunk sent")
            txBuffer = null // Clear TX buffer
            chunk + SW_SUCCESS
        }
    }

    /**
     * Phase 4: Commit Pairing
     */
    private fun handlePhase4(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(apdu.sliceArray(5 until apdu.size), sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                getSharedPreferences("nfc_lock_prefs", MODE_PRIVATE).edit().putBoolean("isPaired", true).apply()
                timeoutHandler.removeCallbacks(timeoutRunnable)
                sendLogToGui("Pairing Complete")
                SW_SUCCESS
            } else { SW_DECRYPTION_FAILED }
        } catch (e: Exception) { SW_DECRYPTION_FAILED }
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        resetBuffers()
    }

    private fun ByteArray.normalize(size: Int): ByteArray {
        if (this.size == size) return this
        if (this.size > size) return this.sliceArray(this.size - size until this.size)
        val res = ByteArray(size)
        System.arraycopy(this, 0, res, size - this.size, this.size)
        return res
    }
}

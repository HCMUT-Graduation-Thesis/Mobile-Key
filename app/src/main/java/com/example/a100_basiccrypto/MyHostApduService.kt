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
import com.example.a100_basiccrypto.ApduConstants.INS_VERIFY_NONCE
import com.example.a100_basiccrypto.ApduConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.ApduConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.ApduConstants.SW_SUCCESS
import com.example.a100_basiccrypto.ApduConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.ApduConstants.TRANSACTION_TIMEOUT_MS
import com.example.a100_basiccrypto.CryptoUtils.toHex
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
    
    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val timeoutRunnable = Runnable {
        handleTimeout()
    }

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
        Log.d(TAG, "RX: ${if (hexCommand.length > 100) hexCommand.take(100) + "..." else hexCommand}")

        // Phase 1: Select AID
        if (commandApdu.size >= 2 && commandApdu[0] == CLA_ISO && commandApdu[1] == 0xA4.toByte()) {
            startTransaction()
            sendLogToGui("Phase 1: Connected to Reader (Select AID success)")
            return SW_SUCCESS
        }

        if (commandApdu[0] != CLA_PROPRIETARY) return SW_UNKNOWN_CMD

        // Restart timeout on each command
        resetTimeout()

        return when (commandApdu[1]) {
            INS_EXCHANGE_AND_DERIVE -> handlePhase2a(commandApdu)
            INS_VERIFY_NONCE -> handlePhase2b(commandApdu)
            INS_EXCHANGE_IMMOBILIZER -> handlePhase3(commandApdu)
            INS_COMMIT_PAIRING -> handlePhase4(commandApdu)
            else -> SW_UNKNOWN_CMD
        }
    }

    private fun startTransaction() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
        currentSessionKey = null
        ephemeralKeyPair = null
    }

    private fun resetTimeout() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, TRANSACTION_TIMEOUT_MS)
    }

    private fun handleTimeout() {
        currentSessionKey = null
        ephemeralKeyPair = null
        sendLogToGui("Transaction Failed (Timeout)")
        Log.e(TAG, "Transaction Timeout Reached")
    }

    /**
     * Phase 2.a: Ephemeral Key Exchange & Session Key Generation (ECC secp256r1)
     */
    private fun handlePhase2a(apdu: ByteArray): ByteArray {
        return try {
            val pubKeyReaderBytes = apdu.sliceArray(5 until 5 + 65)
            val pubKeyReader = CryptoUtils.getPublicKeyFromHex(pubKeyReaderBytes.toHex())

            // Generate Ephemeral Key Pair for HCE
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            ephemeralKeyPair = kpg.generateKeyPair()

            // Calculate Shared Secret
            val sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, pubKeyReader)

            // Derive Session Key using PasswordManager
            val salt = PasswordManager.getPassword(this).toByteArray()
            currentSessionKey = CryptoUtils.deriveSessionKey(
                ikm = sharedSecret,
                salt = salt,
                info = HKDF_INFO.toByteArray(),
                length = 32
            )

            sendLogToGui("Phase 2.a: Session Key generated successfully")
            Log.i(TAG, "Session Key: ${currentSessionKey?.toHex()}")

            val ecPubKey = ephemeralKeyPair!!.public as java.security.interfaces.ECPublicKey
            val x = ecPubKey.w.affineX.toByteArray().normalize(32)
            val y = ecPubKey.w.affineY.toByteArray().normalize(32)
            val ephemeralPubKeyHce = byteArrayOf(0x04.toByte()) + x + y

            ephemeralPubKeyHce + SW_SUCCESS
        } catch (e: Exception) {
            Log.e(TAG, "Phase 2.a Error: ${e.message}")
            SW_INTERNAL_ERROR
        }
    }

    /**
     * Phase 2.b: Nonce Verification (Encrypted AES-GCM)
     */
    private fun handlePhase2b(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val lc = getLc(apdu)
            val encryptedData = apdu.sliceArray(apdu.size - lc until apdu.size)
            val decryptedNonce = CryptoUtils.decryptAesGcm(encryptedData, sessionKey)
            sendLogToGui("Phase 2.b: Nonce verified")

            CryptoUtils.encryptAesGcm(decryptedNonce, sessionKey) + SW_SUCCESS
        } catch (e: Exception) {
            Log.e(TAG, "Phase 2.b Decryption Error: ${e.message}")
            sendLogToGui("Transaction Failed (Decryption Error)")
            SW_DECRYPTION_FAILED
        }
    }

    /**
     * Phase 3: Long Key (Dilithium3) & Immobilizer Token Exchange (Encrypted AES-GCM)
     */
    private fun handlePhase3(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val lc = getLc(apdu)
            val encryptedData = apdu.sliceArray(apdu.size - lc until apdu.size)
            val decryptedData = CryptoUtils.decryptAesGcm(encryptedData, sessionKey)

            // [Long_PK_Reader_Dilithium (Var)] + [Token (64)]
            val token = decryptedData.sliceArray(decryptedData.size - 64 until decryptedData.size).toHex()
            val longPkReader = decryptedData.sliceArray(0 until decryptedData.size - 64).toHex()

            // Save reader info to SharedPreferences
            val prefs = getSharedPreferences("nfc_lock_prefs", MODE_PRIVATE)
            val editor = prefs.edit()
            editor.putString("last_reader_dilithium_pk", longPkReader)
            editor.putString("immobilizer_token", token)
            editor.apply()

            sendLogToGui("Phase 3: Immobilizer Token and Dilithium3 PK received")

            val longPkHce = identityCrypto.getPublicKey()
            CryptoUtils.encryptAesGcm(longPkHce, sessionKey) + SW_SUCCESS
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3 Decryption Error: ${e.message}")
            sendLogToGui("Transaction Failed (Decryption Error)")
            SW_DECRYPTION_FAILED
        }
    }

    /**
     * Phase 4: Commit Pairing (Encrypted AES-GCM)
     */
    private fun handlePhase4(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val lc = getLc(apdu)
            val encryptedData = apdu.sliceArray(apdu.size - lc until apdu.size)
            val decryptedData = CryptoUtils.decryptAesGcm(encryptedData, sessionKey)

            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                getSharedPreferences("nfc_lock_prefs", MODE_PRIVATE).edit().putBoolean("isPaired", true).apply()
                timeoutHandler.removeCallbacks(timeoutRunnable)
                sendLogToGui("Pairing Complete")
                SW_SUCCESS
            } else {
                sendLogToGui("Transaction Failed (Invalid Commit Flag)")
                SW_DECRYPTION_FAILED
            }
        } catch (e: Exception) {
            Log.e(TAG, "Phase 4 Decryption Error: ${e.message}")
            sendLogToGui("Transaction Failed (Decryption Error)")
            SW_DECRYPTION_FAILED
        }
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        currentSessionKey = null
    }

    /**
     * Helper to get Lc for both Short and Extended APDU
     */
    private fun getLc(apdu: ByteArray): Int {
        if (apdu.size < 5) return 0
        val l1 = apdu[4].toInt() and 0xFF
        return if (l1 != 0 || apdu.size < 7) {
            l1
        } else {
            ((apdu[5].toInt() and 0xFF) shl 8) or (apdu[6].toInt() and 0xFF)
        }
    }

    private fun ByteArray.normalize(size: Int): ByteArray {
        if (this.size == size) return this
        if (this.size > size) return this.sliceArray(this.size - size until this.size)
        val res = ByteArray(size)
        System.arraycopy(this, 0, res, size - this.size, this.size)
        return res
    }
}

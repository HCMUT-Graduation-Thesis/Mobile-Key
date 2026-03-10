package com.example.a100_basiccrypto

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.example.a100_basiccrypto.ApduConstants.CLA_ISO
import com.example.a100_basiccrypto.ApduConstants.CLA_PROPRIETARY
import com.example.a100_basiccrypto.ApduConstants.INS_COMMIT_PAIRING
import com.example.a100_basiccrypto.ApduConstants.INS_EXCHANGE_AND_DERIVE
import com.example.a100_basiccrypto.ApduConstants.INS_EXCHANGE_IMMOBILIZER
import com.example.a100_basiccrypto.ApduConstants.INS_VERIFY_NONCE
import com.example.a100_basiccrypto.ApduConstants.SW_DATA_MISMATCH
import com.example.a100_basiccrypto.ApduConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.ApduConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.ApduConstants.SW_SUCCESS
import com.example.a100_basiccrypto.ApduConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.ApduConstants.SW_WRONG_LENGTH
import com.example.a100_basiccrypto.CryptoUtils.hexToBytes
import com.example.a100_basiccrypto.CryptoUtils.toHex

class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcEcdhLock"
        private const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"

        // --- TEST VECTORS & HARDCODED DATA ---
        private const val APP_PRIVATE_KEY_A_HEX = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433"
        private const val APP_PUBLIC_KEY_A_HEX = "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C37725811805271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
        
        private const val PUBLIC_KEY_B_HEX = "04BDD198F673E16ED3FF0C5555E8E6E2A6A3EEA052805C07A358DC137D9DC93213E1D5CA5E54336D9FFA7F0D9CECB01C53BFE5AF9EE29D7D5F67F6BAF8F955CDE5"
        private const val IMMOBILIZER_TOKEN_HEX = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF"
        
        private const val HKDF_INFO = "NFC_OWNER_CONFIRM"
    }

    private var currentSessionKey: ByteArray? = null
    private var isPairingComplete = false

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
        Log.d(TAG, "RX: $hexCommand")

        // Phase 1: Select AID
        if (commandApdu[0] == CLA_ISO && commandApdu[1] == 0xA4.toByte()) {
            resetState()
            sendLogToGui("Phase 1: Select AID successful")
            return SW_SUCCESS
        }

        if (commandApdu[0] != CLA_PROPRIETARY) return SW_UNKNOWN_CMD

        return when (commandApdu[1]) {
            INS_EXCHANGE_AND_DERIVE -> handlePhase2a(commandApdu)
            INS_VERIFY_NONCE -> handlePhase2b(commandApdu)
            INS_EXCHANGE_IMMOBILIZER -> handlePhase3(commandApdu)
            INS_COMMIT_PAIRING -> handlePhase4(commandApdu)
            else -> SW_UNKNOWN_CMD
        }
    }

    private fun resetState() {
        currentSessionKey = null
        isPairingComplete = false
    }

    /**
     * Phase 2.a: ECDH + HKDF
     */
    private fun handlePhase2a(apdu: ByteArray): ByteArray {
        if (apdu.size < 5 || apdu[4].toInt() != 0x41) return SW_WRONG_LENGTH
        return try {
            val pubKeyBBytes = apdu.sliceArray(5 until 5 + 65)
            val privKeyA = CryptoUtils.getPrivateKeyFromHex(APP_PRIVATE_KEY_A_HEX)
            val pubKeyB = CryptoUtils.getPublicKeyFromHex(pubKeyBBytes.toHex())
            
            val sharedSecret = CryptoUtils.generateSharedSecret(privKeyA, pubKeyB)
            currentSessionKey = CryptoUtils.deriveSessionKey(
                ikm = sharedSecret,
                salt = "12345678".toByteArray(),
                info = HKDF_INFO.toByteArray(),
                length = 32
            )
            
            sendLogToGui("Phase 2.a: Session Key Created")
            Log.i(TAG, "Session Key: ${currentSessionKey?.toHex()}")
            
            APP_PUBLIC_KEY_A_HEX.hexToBytes() + SW_SUCCESS
        } catch (e: Exception) {
            SW_INTERNAL_ERROR
        }
    }

    /**
     * Phase 2.b: Nonce Verification
     * Reader sends Plaintext Nonce -> App returns Encrypted Nonce
     */
    private fun handlePhase2b(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val lc = apdu[4].toInt() and 0xFF
            val noncePlaintext = apdu.sliceArray(5 until 5 + lc)
            sendLogToGui("Phase 2.b: Received plaintext nonce [${String(noncePlaintext)}]")

            sendLogToGui("-> Action: Encrypting and sending back")
            val response = CryptoUtils.encryptAesGcm(noncePlaintext, sessionKey)
            response + SW_SUCCESS
        } catch (e: Exception) {
            Log.e(TAG, "P2b Error: ${e.message}")
            sendLogToGui("Phase 2.b: Encryption failed!")
            SW_INTERNAL_ERROR
        }
    }

    /**
     * Phase 3: Exchange Immobilizer (100% Encrypted)
     */
    private fun handlePhase3(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val lc = apdu[4].toInt() and 0xFF
            val encryptedData = apdu.sliceArray(5 until 5 + lc)
            sendLogToGui("Phase 3: Received encrypted data (${lc} bytes)")

            val decryptedData = CryptoUtils.decryptAesGcm(encryptedData, sessionKey)
            sendLogToGui("-> Decryption successful: ${decryptedData.size} bytes")
            
            if (decryptedData.size != 129) {
                sendLogToGui("-> Error: Invalid structure (Expected 129 bytes)")
                return SW_DATA_MISMATCH
            }
            
            val pkBReceived = decryptedData.sliceArray(0 until 65)
            val tokenReceived = decryptedData.sliceArray(65 until 129)
            
            val isPkBMatch = pkBReceived.contentEquals(PUBLIC_KEY_B_HEX.hexToBytes())
            val isTokenMatch = tokenReceived.contentEquals(IMMOBILIZER_TOKEN_HEX.hexToBytes())
            
            sendLogToGui("-> PK_B Check: ${if (isPkBMatch) "Matched" else "Failed"}")
            sendLogToGui("-> Token Check: ${if (isTokenMatch) "Matched" else "Failed"}")
            
            if (isPkBMatch && isTokenMatch) {
                sendLogToGui("Phase 3: Verification complete. Sending encrypted PK_A.")
                val responseData = APP_PUBLIC_KEY_A_HEX.hexToBytes()
                CryptoUtils.encryptAesGcm(responseData, sessionKey) + SW_SUCCESS
            } else {
                sendLogToGui("Phase 3 Error: Data Mismatch")
                SW_DATA_MISMATCH
            }
        } catch (e: Exception) {
            Log.e(TAG, "P3 Error: ${e.message}")
            sendLogToGui("Phase 3: Decryption or authentication error")
            SW_DECRYPTION_FAILED
        }
    }

    /**
     * Phase 4: Commit Pairing (Encrypted)
     */
    private fun handlePhase4(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val lc = apdu[4].toInt() and 0xFF
            val encryptedData = apdu.sliceArray(5 until 5 + lc)
            val decryptedData = CryptoUtils.decryptAesGcm(encryptedData, sessionKey)
            
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                isPairingComplete = true
                sendLogToGui("Phase 4: Pairing Complete!")
                SW_SUCCESS
            } else {
                sendLogToGui("Phase 4: Invalid commit flag")
                SW_DATA_MISMATCH
            }
        } catch (e: Exception) {
            sendLogToGui("Phase 4: Decryption failed")
            SW_DECRYPTION_FAILED
        }
    }

    override fun onDeactivated(reason: Int) {}
}

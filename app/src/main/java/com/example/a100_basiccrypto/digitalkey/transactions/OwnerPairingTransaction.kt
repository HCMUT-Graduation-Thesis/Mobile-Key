package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.KeyState
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.INS_COMMIT_PAIRING
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.INS_EXCHANGE_AND_DERIVE
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.INS_EXCHANGE_IMMOBILIZER
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.INS_VERIFY_NONCE
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.nfc.ApduConstants.SW_UNKNOWN_CMD
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class OwnerPairingTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    private var currentSessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var isComplete = false
    private val HKDF_INFO = "NFC_OWNER_CONFIRM"

    override fun processCommand(apdu: ByteArray): ByteArray {
        val ins = apdu[1]
        return when (ins) {
            INS_EXCHANGE_AND_DERIVE -> handlePhase2a(apdu)
            INS_VERIFY_NONCE -> handlePhase2b(apdu)
            INS_EXCHANGE_IMMOBILIZER -> handlePhase3(apdu)
            INS_COMMIT_PAIRING -> handlePhase4(apdu)
            else -> SW_UNKNOWN_CMD
        }
    }

    override fun resetTransaction() {
        currentSessionKey = null
        ephemeralKeyPair = null
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handlePhase2a(apdu: ByteArray): ByteArray {
        return try {
            val pubKeyReaderBytes = apdu.sliceArray(5 until 5 + 65)
            val pubKeyReader = CryptoUtils.getPublicKeyFromHex(pubKeyReaderBytes.toHex())

            val kpg = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }
            ephemeralKeyPair = kpg.generateKeyPair()

            val sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, pubKeyReader)
            val salt = passwordProvider().toByteArray()
            currentSessionKey = CryptoUtils.deriveSessionKey(sharedSecret, salt, HKDF_INFO.toByteArray(), 32)

            onLog("Phase 2.a: Session Key generated")
            
            val ecPubKey = ephemeralKeyPair!!.public as ECPublicKey
            val x = ecPubKey.w.affineX.toByteArray().normalize(32)
            val y = ecPubKey.w.affineY.toByteArray().normalize(32)
            byteArrayOf(0x04.toByte()) + x + y + SW_SUCCESS
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 2a: ${e.message}")
            SW_INTERNAL_ERROR
        }
    }

    private fun handlePhase2b(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedNonce = CryptoUtils.decryptAesGcm(apdu.sliceArray(5 until apdu.size), sessionKey)
            onLog("Phase 2.b: Nonce verified")
            CryptoUtils.encryptAesGcm(decryptedNonce, sessionKey) + SW_SUCCESS
        } catch (e: Exception) {
            onLog("Phase 2.b: Decryption failed")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handlePhase3(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(apdu.sliceArray(5 until apdu.size), sessionKey)
            
            // [vehiclePublicKey (~1952)] + [immobilizerToken (64)]
            val token = decryptedData.sliceArray(decryptedData.size - 64 until decryptedData.size)
            val vehiclePK = decryptedData.sliceArray(0 until decryptedData.size - 64)

            // Update record
            val record = storageManager.getDigitalKey() ?: DigitalKeyRecord()
            record.vehiclePublicKey = vehiclePK
            record.immobilizerToken = token
            record.devicePublicKey = identityCrypto.getPublicKey()
            storageManager.saveDigitalKey(record)

            onLog("Phase 3: Immobilizer Token received")
            CryptoUtils.encryptAesGcm(record.devicePublicKey!!, sessionKey) + SW_SUCCESS
        } catch (e: Exception) {
            onLog("Phase 3: Decryption failed")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handlePhase4(apdu: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(apdu.sliceArray(5 until apdu.size), sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                val record = storageManager.getDigitalKey()
                record?.let {
                    it.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(it)
                }
                isComplete = true
                onLog("Phase 4: Pairing Complete!")
                SW_SUCCESS
            } else {
                SW_DECRYPTION_FAILED
            }
        } catch (e: Exception) {
            onLog("Phase 4: Decryption failed")
            SW_DECRYPTION_FAILED
        }
    }
}

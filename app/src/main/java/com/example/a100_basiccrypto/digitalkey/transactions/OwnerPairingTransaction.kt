package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.KeyState
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_PAIRING_COMMIT_REQ
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_PAIRING_ENC_PAYLOAD
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_PAIRING_NONCE_REQ
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_PAIRING_PUBKEY_REQ
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_SUCCESS
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

    override fun processCommand(msgId: Byte, payload: ByteArray): ByteArray {
        return when (msgId) {
            MSG_PAIRING_PUBKEY_REQ -> handleExchangePubKey(payload)
            MSG_PAIRING_NONCE_REQ -> handleVerifyNonce(payload)
            MSG_PAIRING_ENC_PAYLOAD -> handleExchangeImmobilizerToken(payload)
            MSG_PAIRING_COMMIT_REQ -> handleCommitPairing(payload)
            else -> byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    override fun resetTransaction() {
        currentSessionKey = null
        ephemeralKeyPair = null
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleExchangePubKey(payload: ByteArray): ByteArray {
        return try {
            val pubKeyReaderBytes = payload.sliceArray(0 until 65)
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

    private fun handleVerifyNonce(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedNonce = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 2.b: Nonce verified")
            CryptoUtils.encryptAesGcm(decryptedNonce, sessionKey) + SW_SUCCESS
        } catch (e: Exception) {
            onLog("Phase 2.b: Decryption failed")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handleExchangeImmobilizerToken(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            
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

    private fun handleCommitPairing(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
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

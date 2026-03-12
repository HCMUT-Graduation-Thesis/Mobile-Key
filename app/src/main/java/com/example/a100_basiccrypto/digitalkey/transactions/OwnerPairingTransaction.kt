package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.CarMetadata
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
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Implementation of the Owner Pairing process.
 * Handlers return raw data payloads only. APDU status words are added by the transport layer.
 */
class OwnerPairingTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    override val transactionType: TransactionType = TransactionType.OWNER_PAIRING

    private var currentSessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var isComplete = false
    
    private val HKDF_INFO = "NFC_OWNER_CONFIRM"
    private val FAST_AUTH_TAG = "DIGITAL_KEY_FAST_AUTH"
    private val gson = Gson()

    override fun processCommand(msgId: Byte, payload: ByteArray): ByteArray {
        return when (msgId) {
            MSG_PAIRING_PUBKEY_REQ -> handleExchangePubKey(payload)
            MSG_PAIRING_NONCE_REQ -> handleVerifyNonce(payload)
            MSG_PAIRING_ENC_PAYLOAD -> handleExchangeVehicleData(payload)
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

            onLog("Phase 2.a: Session Key established")
            
            val ecPubKey = ephemeralKeyPair!!.public as ECPublicKey
            val x = ecPubKey.w.affineX.toByteArray().normalize(32)
            val y = ecPubKey.w.affineY.toByteArray().normalize(32)
            
            // Return raw uncompressed point data (65 bytes)
            byteArrayOf(0x04.toByte()) + x + y 
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
            // Return raw encrypted data only
            CryptoUtils.encryptAesGcm(decryptedNonce, sessionKey)
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 2b: ${e.message}")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handleExchangeVehicleData(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            Log.d("Pairing", "Phase 3: Decrypted Data size = ${decryptedData.size}")
            
            val buffer = ByteBuffer.wrap(decryptedData)
            val record = DigitalKeyRecord()

            // 1. Vehicle Public Key (1952 bytes)
            if (buffer.remaining() >= 1952) {
                val vehiclePK = ByteArray(1952)
                buffer.get(vehiclePK)
                record.vehiclePublicKey = vehiclePK
            }

            // 2. Identification (moduleID: 16 bytes, slotID: 1 byte)
            if (buffer.remaining() >= 17) {
                val moduleID = ByteArray(16)
                buffer.get(moduleID)
                record.moduleID = moduleID
                record.slotID = buffer.get()
            }

            // 3. Counter (4 bytes) & Permissions (4 bytes)
            if (buffer.remaining() >= 8) {
                record.transactionCounter = buffer.int
                record.permissions = buffer.int
            }

            // 4. Validity (16 bytes)
            if (buffer.remaining() >= 16) {
                record.validityStart = buffer.long
                record.validityEnd = buffer.long
            }

            // 5. Immobilizer Token (64 bytes)
            if (buffer.remaining() >= 64) {
                val token = ByteArray(64)
                buffer.get(token)
                record.immobilizerToken = token
            }

            // 6. Metadata
            if (buffer.hasRemaining()) {
                val remaining = ByteArray(buffer.remaining())
                buffer.get(remaining)
                try {
                    val metadataJson = String(remaining)
                    record.carMetadata = gson.fromJson(metadataJson, CarMetadata::class.java)
                    record.friendlyName = record.carMetadata?.modelName ?: "My Vehicle"
                } catch (e: Exception) {
                    Log.w("Pairing", "Failed to parse metadata JSON")
                }
            }

            // 7. Derive Fast Auth Key (K_FA) locally FROM Session Key
            // Requirement: Use dynamic password from UI as salt.
            val salt = passwordProvider().toByteArray()
            record.fastAuthKey = CryptoUtils.deriveSessionKey(
                sessionKey, 
                salt, 
                FAST_AUTH_TAG.toByteArray(), 
                32
            )

            // 8. Calculate Local KeyID (8 bytes slice of SHA-256 PK)
            val devicePubKey = identityCrypto.getPublicKey()
            record.keyID = MessageDigest.getInstance("SHA-256")
                .digest(devicePubKey)
                .sliceArray(0..7)
            
            record.devicePublicKey = devicePubKey
            record.keyState = KeyState.PROVISIONING
            
            storageManager.saveDigitalKey(record)
            onLog("Phase 3: Vehicle Profile stored. KeyID: ${record.keyID?.toHex()}")
            
            // Return raw encrypted Device Public Key only
            CryptoUtils.encryptAesGcm(devicePubKey, sessionKey)
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 3: ${e.message}", e)
            SW_DECRYPTION_FAILED
        }
    }

    private fun handleCommitPairing(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                val records = storageManager.getAllKeys()
                records.lastOrNull { it.keyState == KeyState.PROVISIONING }?.let {
                    it.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(it)
                }
                isComplete = true
                onLog("Phase 4: Pairing Complete!")
                ByteArray(0) // Empty payload for success (Service adds 9000)
            } else {
                SW_DECRYPTION_FAILED
            }
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 4: ${e.message}")
            SW_DECRYPTION_FAILED
        }
    }
}

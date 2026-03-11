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
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Implementation of the Owner Pairing process.
 * Handles Phase 2 (ECDH), Phase 3 (Data Exchange), and Phase 4 (Commit).
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

    /**
     * Phase 2.a: Ephemeral Key Exchange (ECDH)
     */
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

    /**
     * Phase 2.b: Nonce Verification (AES-GCM)
     */
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

    /**
     * Phase 3: Comprehensive Data Exchange.
     * Receives vehicle keys, IDs, permissions, validity, and metadata.
     * FastAuthKey is derived locally from the Session Key.
     */
    private fun handleExchangeVehicleData(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decryptedData)

            // 1. Vehicle Public Key (~1952 bytes)
            val vehiclePK = ByteArray(1952)
            buffer.get(vehiclePK)

            // 2. Identification (moduleID: 16 bytes, slotID: 1 byte)
            val moduleID = ByteArray(16)
            buffer.get(moduleID)
            val slotID = buffer.get()

            // 3. Security (initialCounter: 4 bytes)
            // Note: fastAuthKey is NOT received, it is derived below.
            val initialCounter = buffer.int

            // 4. Lifecycle (permissions: 4 bytes, validity: 16 bytes)
            val permissions = buffer.int
            val validityStart = buffer.long
            val validityEnd = buffer.long

            // 5. Immobilizer Token (64 bytes)
            val token = ByteArray(64)
            buffer.get(token)

            // 6. Metadata (JSON string - remaining bytes)
            val metadataBytes = ByteArray(buffer.remaining())
            buffer.get(metadataBytes)
            val metadataJson = String(metadataBytes)
            val carMetadata = try {
                gson.fromJson(metadataJson, CarMetadata::class.java)
            } catch (e: Exception) {
                CarMetadata(modelName = "Unknown Vehicle")
            }

            // 7. Derive Fast Auth Key (K_FA) locally
            val fastAuthKey = CryptoUtils.deriveSessionKey(
                sessionKey, 
                ByteArray(6),
                FAST_AUTH_TAG.toByteArray(), 
                32
            )

            // Assemble the DigitalKeyRecord
            val record = DigitalKeyRecord().apply {
                this.vehiclePublicKey = vehiclePK
                this.moduleID = moduleID
                this.slotID = slotID
                this.fastAuthKey = fastAuthKey
                this.transactionCounter = initialCounter
                this.permissions = permissions
                this.validityStart = validityStart
                this.validityEnd = validityEnd
                this.immobilizerToken = token
                this.carMetadata = carMetadata
                this.friendlyName = if (carMetadata.modelName.isNotEmpty()) carMetadata.modelName else "My Vehicle"
                this.devicePublicKey = identityCrypto.getPublicKey()
                this.keyState = KeyState.PROVISIONING
            }

            storageManager.saveDigitalKey(record)

            onLog("Phase 3: Vehicle Profile & Metadata received. FastAuthKey derived.")
            
            // Response with Device Public Key (Dilithium) to the reader
            CryptoUtils.encryptAesGcm(record.devicePublicKey!!, sessionKey)
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 3: ${e.message}")
            onLog("Phase 3: Data processing failed")
            SW_DECRYPTION_FAILED
        }
    }

    /**
     * Phase 4: Final Commitment
     */
    private fun handleCommitPairing(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                // Activate the most recent provisioning key
                val records = storageManager.getAllKeys()
                records.lastOrNull { it.keyState == KeyState.PROVISIONING }?.let {
                    it.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(it)
                }
                isComplete = true
                onLog("Phase 4: Pairing Complete! Key is now ACTIVE.")
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

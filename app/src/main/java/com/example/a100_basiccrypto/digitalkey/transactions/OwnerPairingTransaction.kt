package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.CarMetadata
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.KeyState
import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.PHASE_COMMIT
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.PHASE_DATA_SYNC
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.PHASE_KEY_EXCHANGE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.PHASE_PAIRING_REQ
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.PHASE_VERIFY_NONCE
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
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Standard Owner Pairing Implementation with Debug Logging.
 * Updated to save both Public and Private Identity Keys per record.
 */
class OwnerPairingTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    private var currentSessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var isComplete = false
    private var pendingRecord: DigitalKeyRecord? = null
    
    private val HKDF_INFO = "NFC_OWNER_CONFIRM"
    private val FAST_AUTH_TAG = "DIGITAL_KEY_FAST_AUTH"
    private val gson = Gson()

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return when (frame.msgId) {
            PHASE_PAIRING_REQ -> handleStartPairing()
            PHASE_KEY_EXCHANGE -> handleExchangePubKey(frame.payload)
            PHASE_VERIFY_NONCE -> handleVerifyNonce(frame.payload)
            PHASE_DATA_SYNC -> handleExchangeVehicleData(frame.payload)
            PHASE_COMMIT -> handleCommitPairing(frame.payload)
            else -> byteArrayOf(0xE0.toByte())
        }
    }

    override fun resetTransaction() {
        currentSessionKey = null
        ephemeralKeyPair = null
        isComplete = false
        pendingRecord = null
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleStartPairing(): ByteArray {
        onLog("Phase 1: Pairing Request Received")
        return ByteArray(0)
    }

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
            
            byteArrayOf(0x04.toByte()) + x + y 
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 2a: ${e.message}")
            SW_INTERNAL_ERROR
        }
    }

    private fun handleVerifyNonce(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decrypted2b = CryptoUtils.decryptAesGcm(payload, sessionKey)
            
            onLog("Phase 2.b: Nonce verified")
            
            val hcePubKey = identityCrypto.getPublicKey()
            val response = decrypted2b.sliceArray(0 until 16) + hcePubKey
            
            CryptoUtils.encryptAesGcm(response, sessionKey)
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 2b: ${e.message}")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handleExchangeVehicleData(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            
            onLog("Phase 3: Data Received (${decryptedData.size} bytes)")
            
            val buffer = ByteBuffer.wrap(decryptedData)
            val record = DigitalKeyRecord()

            // 1. Vehicle Public Key (Fixed 1952 bytes for Dilithium3)
            if (buffer.remaining() >= 1952) {
                val vehiclePK = ByteArray(1952)
                buffer.get(vehiclePK)
                record.vehiclePublicKey = vehiclePK
            }

            // 2. KeyID (Fixed 8 bytes)
            if (buffer.remaining() >= 8) {
                val kid = ByteArray(8)
                buffer.get(kid)
                record.keyID = kid
            }

            // 3. ModuleID (16) + SlotID (1)
            if (buffer.remaining() >= 17) {
                val mid = ByteArray(16)
                buffer.get(mid)
                record.moduleID = mid
                record.slotID = buffer.get()
            }

            // 4. Counter (4) + Permissions (4)
            if (buffer.remaining() >= 8) {
                record.transactionCounter = buffer.int
                record.permissions = buffer.int
            }

            // 5. Validity Start (8) + End (8)
            if (buffer.remaining() >= 16) {
                record.validityStart = buffer.long
                record.validityEnd = buffer.long
            }

            // 6. Immobilizer Token (64 bytes)
            if (buffer.remaining() >= 64) {
                val token = ByteArray(64)
                buffer.get(token)
                record.immobilizerToken = token
            }

            // 7. Metadata JSON
            if (buffer.hasRemaining()) {
                val remaining = ByteArray(buffer.remaining())
                buffer.get(remaining)
                val metadataStr = String(remaining, Charsets.UTF_8).trim { it <= ' ' || it == '\u0000' }
                
                try {
                    if (metadataStr.isNotEmpty()) {
                        record.carMetadata = gson.fromJson(metadataStr, CarMetadata::class.java)
                        record.friendlyName = record.carMetadata?.modelName ?: "My Vehicle"
                    }
                } catch (e: Exception) {
                    Log.e("Pairing", "Metadata parse failed")
                }
            }

            val salt = passwordProvider().toByteArray()
            record.fastAuthKey = CryptoUtils.deriveSessionKey(sessionKey, salt, FAST_AUTH_TAG.toByteArray(), 32)
            
            // CRITICAL: Save both keys for this specific record (Unique per Vehicle)
            record.devicePublicKey = identityCrypto.getPublicKey()
            record.devicePrivateKey = identityCrypto.getPrivateKey()
            
            record.keyState = KeyState.PROVISIONING
            
            pendingRecord = record
            storageManager.saveDigitalKey(record)
            onLog("Phase 3 Complete. Identity KeyPair saved for KeyID: ${record.keyID?.toHex()}")
            
            // Response to Reader (Confirmation with Public Key)
            CryptoUtils.encryptAesGcm(record.devicePublicKey!!, sessionKey)
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 3: ${e.message}")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handleCommitPairing(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                val recordToActivate = pendingRecord ?: storageManager.getAllKeys().lastOrNull { it.keyState == KeyState.PROVISIONING }
                if (recordToActivate != null) {
                    recordToActivate.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(recordToActivate)
                    onLog("Phase 4: Pairing Complete! Status: ACTIVE")
                    isComplete = true
                    ByteArray(0)
                } else {
                    SW_DECRYPTION_FAILED
                }
            } else {
                SW_DECRYPTION_FAILED
            }
        } catch (e: Exception) {
            Log.e("Pairing", "Error Phase 4: ${e.message}")
            SW_DECRYPTION_FAILED
        }
    }
}

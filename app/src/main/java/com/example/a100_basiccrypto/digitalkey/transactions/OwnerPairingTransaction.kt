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

class OwnerPairingTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    companion object {
        private const val TAG = "OwnerPairing"
    }

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
            Log.e(TAG, "Error Phase 2a: ${e.message}")
            SW_INTERNAL_ERROR
        }
    }

    private fun handleVerifyNonce(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decrypted2b = CryptoUtils.decryptAesGcm(payload, sessionKey)
            
            onLog("Phase 2.b: Nonce verified")
            
            // Return "original" Public Key (Full X.509)
            val hcePubKey = identityCrypto.getPublicKey()
            Log.d(TAG, "Phase 2.b: Sending App Identity Public Key to Reader, size: ${hcePubKey.size} bytes")
            val response = decrypted2b.sliceArray(0 until 16) + hcePubKey
            
            CryptoUtils.encryptAesGcm(response, sessionKey)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 2b: ${e.message}")
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

            // Read "original" Vehicle Public Key with ASN.1 DER length parsing.
            // Payload = [VehiclePK (Variable)] + [KeyID:8] + [ModuleID:16] + [SlotID:1] + [Counter:4] + [Perms:4] + [Start:8] + [End:8] + [Token:64] + [Metadata...]
            
            val fixedFieldsSize = 113
            Log.d(TAG, "Phase 3: Total Decrypted Payload Size: ${decryptedData.size} bytes")
            
            if (buffer.remaining() > fixedFieldsSize) {
                // Peek at the first bytes to determine if it's X.509 (DER) or Raw
                val currentPos = buffer.position()
                val firstByte = buffer.get(currentPos)
                
                var actualPkSize = 1952 // Default fallback for Raw Dilithium3
                
                if (firstByte == 0x30.toByte()) { // 0x30 is the ASN.1 SEQUENCE tag (X.509 starts with this)
                    val lenByte1 = buffer.get(currentPos + 1).toInt() and 0xFF
                    actualPkSize = when {
                        lenByte1 == 0x82 -> {
                            // Long form, 2 bytes length
                            val b2 = buffer.get(currentPos + 2).toInt() and 0xFF
                            val b3 = buffer.get(currentPos + 3).toInt() and 0xFF
                            ((b2 shl 8) or b3) + 4 // +4 for Tag(1) + LenHeader(3)
                        }
                        lenByte1 == 0x81 -> {
                            // Long form, 1 byte length
                            (buffer.get(currentPos + 2).toInt() and 0xFF) + 3
                        }
                        lenByte1 < 0x80 -> {
                            // Short form
                            lenByte1 + 2
                        }
                        else -> 1952
                    }
                    Log.d(TAG, "Phase 3: Detected X.509 Public Key header. Parsed size: $actualPkSize bytes")
                } else {
                    Log.d(TAG, "Phase 3: No X.509 header found. Using default Raw size: 1952 bytes")
                }

                // Extract exactly the amount of bytes needed for the Public Key
                if (buffer.remaining() >= actualPkSize) {
                    val vehiclePK = ByteArray(actualPkSize)
                    buffer.get(vehiclePK)
                    record.vehiclePublicKey = vehiclePK
                    Log.d(TAG, "Vehicle PK extracted: ${vehiclePK.size} bytes")
                } else {
                    Log.e(TAG, "Phase 3 Error: Buffer underflow for PK. Expected $actualPkSize but only ${buffer.remaining()} left.")
                    val available = buffer.remaining()
                    val fallbackPK = ByteArray(available)
                    buffer.get(fallbackPK)
                    record.vehiclePublicKey = fallbackPK
                }
            } else {
                Log.w(TAG, "Warning Phase 3: Buffer remaining (${buffer.remaining()}) is not enough for fixed fields ($fixedFieldsSize)")
            }

            // 2. KeyID (8 bytes)
            if (buffer.remaining() >= 8) {
                val kid = ByteArray(8)
                buffer.get(kid)
                record.keyID = kid
                Log.d(TAG, "KeyID extracted: ${kid.toHex()}")
            }

            // 3. ModuleID (16) + SlotID (1)
            if (buffer.remaining() >= 17) {
                val mid = ByteArray(16)
                buffer.get(mid)
                record.moduleID = mid
                record.slotID = buffer.get()
                Log.d(TAG, "ModuleID extracted: ${mid.toHex()}, SlotID: ${record.slotID}")
            }

            // 4. Counter (4) + Permissions (4)
            if (buffer.remaining() >= 8) {
                record.transactionCounter = buffer.int
                record.permissions = buffer.int
                Log.d(TAG, "Counter: ${record.transactionCounter}, Permissions: ${record.permissions}")
            }

            // 5. Validity Start (8) + End (8)
            if (buffer.remaining() >= 16) {
                record.validityStart = buffer.long
                record.validityEnd = buffer.long
                Log.d(TAG, "Validity: ${record.validityStart} to ${record.validityEnd}")
            }

            // 6. Immobilizer Token (64 bytes)
            if (buffer.remaining() >= 64) {
                val token = ByteArray(64)
                buffer.get(token)
                record.immobilizerToken = token
                Log.d(TAG, "Immobilizer Token extracted (64 bytes)")
            }

            // 7. Metadata JSON (Remaining part)
            if (buffer.hasRemaining()) {
                val remainingCount = buffer.remaining()
                val remaining = ByteArray(remainingCount)
                buffer.get(remaining)
                val metadataStr = String(remaining, Charsets.UTF_8).trim { it <= ' ' || it == '\u0000' }
                Log.d(TAG, "Metadata raw string size: $remainingCount bytes")
                try {
                    if (metadataStr.isNotEmpty()) {
                        record.carMetadata = gson.fromJson(metadataStr, CarMetadata::class.java)
                        record.friendlyName = record.carMetadata?.modelName ?: "My Vehicle"
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Metadata parse failed: ${e.message}")
                }
            }

            val salt = passwordProvider().toByteArray()
            record.fastAuthKey = CryptoUtils.deriveSessionKey(sessionKey, salt, FAST_AUTH_TAG.toByteArray(), 32)
            
            // IMPORTANT: Save ORIGINAL Public/Private Key (Full encoded bytes)
            record.devicePublicKey = identityCrypto.getPublicKey()
            record.devicePrivateKey = identityCrypto.getPrivateKey()
            Log.d(TAG, "Saving Record: Device PK size: ${record.devicePublicKey?.size}, Device SK size: ${record.devicePrivateKey?.size}")
            
            record.keyState = KeyState.PROVISIONING
            pendingRecord = record
            storageManager.saveDigitalKey(record)
            
            onLog("Phase 3 Complete. Full Identity Keys saved.")
            
            // Respond to Reader with the App's original Public Key
            CryptoUtils.encryptAesGcm(record.devicePublicKey!!, sessionKey)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 3: ${e.message}")
            Log.e(TAG, "Phase 3 Exception Details: ", e)
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
                    onLog("Phase 4: Pairing Complete! Key is ACTIVE")
                    isComplete = true
                    ByteArray(0)
                } else {
                    Log.e(TAG, "Error Phase 4: No pending record to activate")
                    SW_DECRYPTION_FAILED
                }
            } else {
                Log.e(TAG, "Error Phase 4: Invalid commitment signal")
                SW_DECRYPTION_FAILED
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 4: ${e.message}")
            Log.e(TAG, "Phase 4 Exception Details: ", e)
            SW_DECRYPTION_FAILED
        }
    }
}

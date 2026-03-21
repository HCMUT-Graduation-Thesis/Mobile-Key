package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_DATA_SYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_KEY_EXCHANGE
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_PAIRING_REQ
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_VERIFY_NONCE
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_INTERNAL_ERROR
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.security.KeyPair

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
            onLog("Phase 2.a: Key Exchange")
            val pubKeyReaderBytes = payload.sliceArray(0 until 65)
            
            // Use HandshakeProtector to parse the reader's public key
            val pubKeyReader = HandshakeProtector.parseUncompressedPublicKey(pubKeyReaderBytes)

            // Use HandshakeProtector to generate session keys
            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
            
            val salt = passwordProvider().toByteArray()
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, pubKeyReader, salt, HKDF_INFO
            )

            onLog("Phase 2.a: Session Key established")
            
            // Return uncompressed raw public key
            HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public)
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
            val fixedFieldsSize = 113
            Log.d(TAG, "Phase 3: Total Decrypted Payload Size: ${decryptedData.size} bytes")
            
            if (buffer.remaining() > fixedFieldsSize) {
                val currentPos = buffer.position()
                val firstByte = buffer.get(currentPos)
                
                var actualPkSize = 1952 // Default fallback
                
                if (firstByte == 0x30.toByte()) {
                    val lenByte1 = buffer.get(currentPos + 1).toInt() and 0xFF
                    actualPkSize = when {
                        lenByte1 == 0x82 -> {
                            val b2 = buffer.get(currentPos + 2).toInt() and 0xFF
                            val b3 = buffer.get(currentPos + 3).toInt() and 0xFF
                            ((b2 shl 8) or b3) + 4
                        }
                        lenByte1 == 0x81 -> {
                            (buffer.get(currentPos + 2).toInt() and 0xFF) + 3
                        }
                        lenByte1 < 0x80 -> {
                            lenByte1 + 2
                        }
                        else -> 1952
                    }
                }

                if (buffer.remaining() >= actualPkSize) {
                    val vehiclePK = ByteArray(actualPkSize)
                    buffer.get(vehiclePK)
                    record.core.vehiclePublicKey = vehiclePK
                    Log.d(TAG, "Vehicle PK extracted: ${vehiclePK.size} bytes")
                } else {
                    val available = buffer.remaining()
                    val fallbackPK = ByteArray(available)
                    buffer.get(fallbackPK)
                    record.core.vehiclePublicKey = fallbackPK
                }
            }

            // 2. KeyID (8 bytes)
            if (buffer.remaining() >= 8) {
                val kid = ByteArray(8)
                buffer.get(kid)
                record.core.keyID = kid
                Log.d(TAG, "KeyID extracted: ${kid.toHex()}")
            }

            // 3. ModuleID (16) + SlotID (1)
            if (buffer.remaining() >= 17) {
                val mid = ByteArray(16)
                buffer.get(mid)
                record.core.moduleID = mid
                record.core.slotID = buffer.get()
                Log.d(TAG, "ModuleID extracted: ${mid.toHex()}, SlotID: ${record.core.slotID}")
            }

            // 4. Counter (4) + Permissions (4)
            if (buffer.remaining() >= 8) {
                record.core.transactionCounter = buffer.int
                record.core.permissions = buffer.int
                Log.d(TAG, "Counter: ${record.core.transactionCounter}, Permissions: ${record.core.permissions}")
            }

            // 5. Validity Start (8) + End (8)
            if (buffer.remaining() >= 16) {
                record.core.validityStart = buffer.long
                record.core.validityEnd = buffer.long
                Log.d(TAG, "Validity: ${record.core.validityStart} to ${record.core.validityEnd}")
            }

            // 6. Immobilizer Token (64 bytes)
            if (buffer.remaining() >= 64) {
                val token = ByteArray(64)
                buffer.get(token)
                record.core.immobilizerToken = token
                Log.d(TAG, "Immobilizer Token extracted (64 bytes)")
            }

            // 7. Metadata JSON (Remaining part)
            if (buffer.hasRemaining()) {
                val remainingCount = buffer.remaining()
                val remaining = ByteArray(remainingCount)
                buffer.get(remaining)
                val metadataStr = String(remaining, Charsets.UTF_8).trim { it <= ' ' || it == '\u0000' }
                try {
                    if (metadataStr.isNotEmpty()) {
                        record.core.carMetadata = gson.fromJson(metadataStr, CarMetadata::class.java)
                        record.friendlyName = record.core.carMetadata?.modelName ?: "My Vehicle"
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Metadata parse failed: ${e.message}")
                }
            }

            // Use the same HKDF logic through CryptoUtils
            val salt = passwordProvider().toByteArray()
            record.core.fastAuthKey = CryptoUtils.deriveSessionKey(sessionKey, salt, FAST_AUTH_TAG.toByteArray(), 32)
            
            record.devicePrivateKey = identityCrypto.getPrivateKey()
            record.core.devicePublicKey = identityCrypto.getPublicKey()
            
            record.core.keyState = KeyState.PROVISIONING
            pendingRecord = record
            storageManager.saveDigitalKey(record)
            
            onLog("Phase 3 Complete. Full Identity Keys saved.")
            CryptoUtils.encryptAesGcm(record.core.devicePublicKey!!, sessionKey)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 3: ${e.message}")
            SW_DECRYPTION_FAILED
        }
    }

    private fun handleCommitPairing(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                val recordToActivate = pendingRecord ?: storageManager.getAllKeys().lastOrNull { it.core.keyState == KeyState.PROVISIONING }
                if (recordToActivate != null) {
                    recordToActivate.core.keyState = KeyState.ACTIVE
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
            SW_DECRYPTION_FAILED
        }
    }
}

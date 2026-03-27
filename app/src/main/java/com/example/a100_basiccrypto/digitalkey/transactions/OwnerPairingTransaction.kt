package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_DATA_SYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_KEY_EXCHANGE
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_PAIRING_REQ
import com.example.a100_basiccrypto.shared.command.MessageConstants.PHASE_VERIFY_NONCE
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.security.KeyPair

/**
 * Owner Pairing Transaction - Updated for IPassiveTransport.
 */
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
    
    private val gson = Gson()

    override fun processCommand(frame: LogicalFrame, transport: IPassiveTransport): LogicalResponse {
        return when (frame.msgId) {
            PHASE_PAIRING_REQ -> handleStartPairing()
            PHASE_KEY_EXCHANGE -> handleExchangePubKey(frame.payload)
            PHASE_VERIFY_NONCE -> handleVerifyNonce(frame.payload)
            PHASE_DATA_SYNC -> handleExchangeVehicleData(frame.payload)
            PHASE_COMMIT -> handleCommitPairing(frame.payload)
            else -> LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    override fun resetTransaction() {
        currentSessionKey = null
        ephemeralKeyPair = null
        isComplete = false
        pendingRecord = null
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleStartPairing(): LogicalResponse {
        onLog("Phase 1: Pairing Request Received")
        return LogicalResponse(MSG_GLOBAL_SUCCESS)
    }

    private fun handleExchangePubKey(payload: ByteArray): LogicalResponse {
        return try {
            onLog("Phase 2.a: Key Exchange")
            val pubKeyReaderBytes = payload.sliceArray(0 until 65)
            val pubKeyReader = HandshakeProtector.parseUncompressedPublicKey(pubKeyReaderBytes)

            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
            
            val salt = passwordProvider().toByteArray()
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, pubKeyReader, salt, CryptoConstants.OWNER_SESSION_INFO
            )

            onLog("Phase 2.a: Session Key established")
            val responseData = HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public)
            LogicalResponse(MSG_GLOBAL_SUCCESS, responseData)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 2a: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun handleVerifyNonce(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(MSG_ERR_GENERAL)
        return try {
            val decrypted2b = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 2.b: Nonce verified")
            
            val hcePubKey = identityCrypto.getPublicKey()
            val responseData = decrypted2b.sliceArray(0 until 16) + hcePubKey
            val encrypted = CryptoUtils.encryptAesGcm(responseData, sessionKey)
            LogicalResponse(MSG_GLOBAL_SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 2b: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun handleExchangeVehicleData(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(MSG_ERR_GENERAL)
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 3: Data Received")
            
            val buffer = ByteBuffer.wrap(decryptedData)
            val record = DigitalKeyRecord()

            if (buffer.remaining() >= CryptoConstants.ML_DSA_65_PK_SIZE) {
                val vehiclePK = ByteArray(CryptoConstants.ML_DSA_65_PK_SIZE)
                buffer.get(vehiclePK)
                record.core.vehiclePublicKey = vehiclePK
            } else return LogicalResponse(MSG_ERR_GENERAL)

            if (buffer.remaining() >= 8) {
                val kid = ByteArray(8)
                buffer.get(kid)
                record.core.keyID = kid
            }

            if (buffer.remaining() >= 17) {
                val mid = ByteArray(16)
                buffer.get(mid)
                record.core.moduleID = mid
                record.core.slotID = buffer.get()
            }

            if (buffer.remaining() >= 8) {
                record.core.transactionCounter = buffer.int
                record.core.permissions = buffer.int
            }

            if (buffer.remaining() >= 16) {
                record.core.validityStart = buffer.long
                record.core.validityEnd = buffer.long
            }

            if (buffer.remaining() >= 64) {
                val token = ByteArray(64)
                buffer.get(token)
                record.core.immobilizerToken = token
            }

            if (buffer.hasRemaining()) {
                val remaining = ByteArray(buffer.remaining())
                buffer.get(remaining)
                val metadataStr = String(remaining, Charsets.UTF_8).trim { it <= ' ' || it == '\u0000' }
                try {
                    if (metadataStr.isNotEmpty()) {
                        record.core.carMetadata = gson.fromJson(metadataStr, CarMetadata::class.java)
                        record.friendlyName = record.core.carMetadata?.modelName ?: "My Vehicle"
                    }
                } catch (e: Exception) { Log.e(TAG, "Metadata error: ${e.message}") }
            }

            val salt = passwordProvider().toByteArray()
            record.core.fastAuthKey = CryptoUtils.deriveSessionKey(sessionKey, salt, CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32)
            
            record.devicePrivateKey = identityCrypto.getPrivateKey()
            record.core.devicePublicKey = identityCrypto.getPublicKey()
            
            record.core.keyState = KeyState.PROVISIONING
            pendingRecord = record
            storageManager.saveDigitalKey(record)
            
            onLog("Phase 3 Complete. Key saved.")
            val encrypted = CryptoUtils.encryptAesGcm(record.core.devicePublicKey!!, sessionKey)
            LogicalResponse(MSG_GLOBAL_SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 3: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun handleCommitPairing(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(MSG_ERR_GENERAL)
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                val recordToActivate = pendingRecord ?: storageManager.getAllKeys().lastOrNull { it.core.keyState == KeyState.PROVISIONING }
                if (recordToActivate != null) {
                    recordToActivate.core.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(recordToActivate)
                    onLog("Phase 4: Pairing Complete! Key is ACTIVE")
                    isComplete = true
                    LogicalResponse(MSG_GLOBAL_SUCCESS)
                } else LogicalResponse(MSG_ERR_GENERAL)
            } else LogicalResponse(MSG_ERR_GENERAL)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 4: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }
}

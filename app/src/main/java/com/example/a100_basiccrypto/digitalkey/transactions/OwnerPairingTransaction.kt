package com.example.a100_basiccrypto.digitalkey.transactions

import android.content.Context
import android.util.Log
import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.OwnerPairing
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.security.KeyPair

/**
 * Owner Pairing Transaction - Updated for BLE L2CAP Insecure flow.
 * Removed Level 4 OOB security parameters and BLE routing parameters from payload.
 */
class OwnerPairingTransaction(
    private val context: Context,
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
            OwnerPairing.PHASE_REQ -> handleStartPairing()
            OwnerPairing.PHASE_KEY_EXCHANGE -> handleExchangePubKey(frame.payload)
            OwnerPairing.PHASE_VERIFY_NONCE -> handleVerifyNonce(frame.payload)
            OwnerPairing.PHASE_DATA_SYNC -> handleExchangeVehicleData(frame.payload)
            OwnerPairing.PHASE_COMMIT -> handleCommitPairing(frame.payload)
            else -> LogicalResponse(Status.ERR_GENERAL)
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
        onLog("Phase 1: Pairing Request (L2CAP Insecure Mode)")
        return LogicalResponse(Status.SUCCESS)
    }

    private fun handleExchangePubKey(payload: ByteArray): LogicalResponse {
        return try {
            val pubKeyReader = HandshakeProtector.parseUncompressedPublicKey(payload.sliceArray(0 until 65))
            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, 
                pubKeyReader, 
                passwordProvider().toByteArray(),
                CryptoConstants.OWNER_SESSION_INFO
            )
            LogicalResponse(Status.SUCCESS, HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public))
        } catch (e: Exception) { 
            Log.e(TAG, "Key Exchange Error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL) 
        }
    }

    private fun handleVerifyNonce(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            // Echo nonce (16b) + App Identity PK
            val responseData = decrypted.sliceArray(0 until 16) + identityCrypto.getPublicKey()
            LogicalResponse(Status.SUCCESS, CryptoUtils.encryptAesGcm(responseData, sessionKey))
        } catch (e: Exception) { 
            Log.e(TAG, "Verify Nonce Error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL) 
        }
    }

    private fun handleExchangeVehicleData(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 3: Data Received from Vehicle")

            val buffer = ByteBuffer.wrap(decryptedData)
            val record = DigitalKeyRecord()

            // 1. Dilithium PK (1952)
            val vehiclePK = ByteArray(CryptoConstants.ML_DSA_65_PK_SIZE)
            buffer.get(vehiclePK)
            record.core.vehiclePublicKey = vehiclePK

            // 2. Metadata & Identifiers
            val kid = ByteArray(8); buffer.get(kid)
            record.core.keyID = kid

            val mid = ByteArray(16); buffer.get(mid)
            record.core.moduleID = mid

            record.core.slotID = buffer.get()
            record.core.transactionCounter = buffer.int
            record.core.permissions = buffer.int
            record.core.validityStart = buffer.long
            record.core.validityEnd = buffer.long

            val token = ByteArray(64); buffer.get(token)
            record.core.immobilizerToken = token

            // 3. BLE Connectivity - REMOVED Address and PSM from payload

            // 4. Metadata JSON (Remaining)
            val metaLen = buffer.remaining()
            if (metaLen > 0) {
                val metaBytes = ByteArray(metaLen); buffer.get(metaBytes)
                try {
                    record.core.carMetadata = gson.fromJson(String(metaBytes), CarMetadata::class.java)
                    record.friendlyName = record.core.carMetadata?.modelName ?: "My Vehicle"
                } catch (e: Exception) {
                    onLog("Metadata parse warning: ${e.message}")
                }
            }

            // 5. Fast Auth Key Derivation
            onLog("Phase 3: Deriving Fast Auth Key...")
            val salt = passwordProvider().toByteArray()
            record.core.fastAuthKey = CryptoUtils.deriveSessionKey(
                sessionKey, salt, CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32
            )

            record.devicePrivateKey = identityCrypto.getPrivateKey()
            record.core.devicePublicKey = identityCrypto.getPublicKey()
            record.core.keyState = KeyState.PROVISIONING
            pendingRecord = record
            storageManager.saveDigitalKey(record)

            // 6. Prepare Response: App -> Vehicle (Simplified)
            onLog("Phase 3: Sending App Identity...")
            
            // Response: PK(1952) only - Address removed
            val response = ByteBuffer.allocate(CryptoConstants.ML_DSA_65_PK_SIZE).apply {
                put(record.core.devicePublicKey!!)
            }.array()

            LogicalResponse(Status.SUCCESS, CryptoUtils.encryptAesGcm(response, sessionKey))
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3 Error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleCommitPairing(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size == 1 && decrypted[0] == 0x01.toByte()) {
                pendingRecord?.let { 
                    it.core.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(it)
                    onLog("Phase 4: Pairing Active!")
                }
                isComplete = true
                LogicalResponse(Status.SUCCESS)
            } else LogicalResponse(Status.ERR_GENERAL)
        } catch (e: Exception) { 
            Log.e(TAG, "Commit Phase Error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL) 
        }
    }
}

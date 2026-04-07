package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.Admin
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.SecureRandom

/**
 * Standard Transaction V1.3.0 Implementation - Updated for IPassiveTransport and Pure Sync flow.
 */
class StandardTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    private var currentSessionKey: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var appNonce: ByteArray? = null
    private var activeRecord: DigitalKeyRecord? = null

    private var stagedFastKey: ByteArray? = null
    private var stagedCounter: Int = 0

    private var isCarVerified = false
    private var isDeviceVerified = false
    private var isComplete = false

    override fun processCommand(frame: LogicalFrame, transport: IPassiveTransport): LogicalResponse {
        return when (frame.msgId) {
            Admin.PHASE_AUTH_INIT -> handleAuthInit(frame.payload)
            Admin.PHASE_MUTUAL_VERIFY -> handleMutualVerify(frame.payload)
            Admin.PHASE_ACTION_SYNC -> ifFullAuth { handleActionSync(frame.payload) }
            Admin.PHASE_FINAL_COMMIT -> ifFullAuth { handleFinalCommit(frame.payload) }
            else -> LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun ifFullAuth(action: () -> LogicalResponse): LogicalResponse {
        return if (isCarVerified && isDeviceVerified) action()
        else LogicalResponse(Status.ERR_AUTH_FAIL)
    }

    override fun resetTransaction() {
        currentSessionKey = null
        sharedSecret = null
        ephemeralKeyPair = null
        appNonce = null
        activeRecord = null
        stagedFastKey = null
        stagedCounter = 0
        isCarVerified = false
        isDeviceVerified = false
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleAuthInit(payload: ByteArray): LogicalResponse {
        return try {
            onLog("STD: Phase 1 - Key Exchange")
            
            // Find the starting position of the Public Key (0x04)
            val startIndex = payload.indexOf(0x04.toByte())
            if (startIndex == -1 || payload.size - startIndex < 65) {
                onLog("Error: Invalid AuthInit payload structure")
                return LogicalResponse(Status.ERR_GENERAL)
            }

            // 1. Extract ModuleID from the data preceding the Public Key
            val moduleId = payload.sliceArray(0 until startIndex)
            if (moduleId.isEmpty()) {
                onLog("Error: ModuleID missing in AuthInit. Vehicle must send ModuleID.")
                return LogicalResponse(Status.ERR_AUTH_FAIL)
            }

            // 2. Look up and Store the Key record based on the provided ModuleID
            val record = storageManager.getAllKeys().find { it.moduleID?.contentEquals(moduleId) == true }
                ?: run {
                    onLog("Error: No paired key found for ModuleID: ${moduleId.toHex()}")
                    return LogicalResponse(Status.ERR_AUTH_FAIL)
                }
            
            activeRecord = record // Store active record for subsequent phases

            // 3. Extract Vehicle Public Key
            val vehiclePKBytes = payload.sliceArray(startIndex until startIndex + 65)
            val vehicleEphemeralPK = HandshakeProtector.parseUncompressedPublicKey(vehiclePKBytes)

            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()

            // 4. Use Immobilizer Token from the identified record as Salt
            val salt = record.immobilizerToken ?: throw IllegalStateException("Record missing Immobilizer Token")
            
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, 
                vehicleEphemeralPK, 
                salt, 
                CryptoConstants.STD_SESSION_INFO
            )

            sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehicleEphemeralPK)
            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            val responseData = HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public) + appNonce!!
            LogicalResponse(Status.SUCCESS, responseData)
        } catch (e: Exception) {
            Log.e("StandardTx", "AuthInit error: ${e.message}")
            onLog("AuthInit Error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleMutualVerify(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
        val record = activeRecord ?: return LogicalResponse(Status.ERR_AUTH_FAIL) // Use stored record
        
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decrypted)

            // Adjusted size check: Sig (3309) + Challenge (16) = 3325 (ModuleID removed from Phase 2)
            if (buffer.remaining() < CryptoConstants.ML_DSA_65_SIG_SIZE + 16) return LogicalResponse(Status.ERR_GENERAL)

            val vehicleSig = ByteArray(CryptoConstants.ML_DSA_65_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            val vehiclePK = record.vehiclePublicKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
            
            if (!identityCrypto.verify(appNonce!!, vehicleSig, vehiclePK)) {
                onLog("Error: Vehicle PQC Sig Invalid")
                return LogicalResponse(Status.ERR_AUTH_FAIL)
            }
            
            isCarVerified = true

            val deviceSK = record.devicePrivateKey ?: return LogicalResponse(Status.ERR_GENERAL)
            val appSig = identityCrypto.sign(readerChallenge, deviceSK)
            
            isDeviceVerified = true
            onLog("STD: Mutual Auth Success")
            val encrypted = CryptoUtils.encryptAesGcm((record.core.keyID ?: ByteArray(8)) + appSig, sessionKey)
            LogicalResponse(Status.SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e("StandardTx", "MutualVerify error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleActionSync(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)

        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            
            // Logic for NFC: Expecting empty payload for Pure Sync
            if (decrypted.isEmpty()) {
                onLog("STD: Pure Sync Request received.")
            } else {
                onLog("STD: Action Sync with command (Size: ${decrypted.size}B)")
                // Advanced command logic can be handled here for BLE if needed
            }
            
            val responseData = byteArrayOf(Admin.STD_MSG_SYNC_OK)
            val encrypted = CryptoUtils.encryptAesGcm(responseData, sessionKey)
            LogicalResponse(Status.SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e("StandardTx", "ActionSync error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleFinalCommit(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
        val record = activeRecord ?: return LogicalResponse(Status.ERR_GENERAL)
        val secret = sharedSecret ?: return LogicalResponse(Status.ERR_GENERAL)
        val immotoken = record.immobilizerToken ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size < 2) return LogicalResponse(Status.ERR_GENERAL)

            val execResult = decrypted[0]
            val commitMarker = decrypted[1]

            if (execResult == Admin.STD_EXEC_SUCCESS && commitMarker == Admin.STD_COMMIT_MARKER) {
                // Always rotate the fast auth key during Standard Transaction
                val newFastKey = CryptoUtils.deriveSessionKey(
                    secret,
                    immotoken,
                    CryptoConstants.FAST_KEY_REFRESH.toByteArray(),
                    32
                )
                stagedFastKey = newFastKey
                stagedCounter = 0
                storageManager.updateFastKeyAndCounter(record.core.keyID!!, newFastKey, stagedCounter)
                isComplete = true
                onLog("STD: Final Commit Success. Key is now ACTIVE.")
                LogicalResponse(Status.SUCCESS)
            } else {
                onLog("STD Error: Commit markers mismatch.")
                LogicalResponse(Status.ERR_GENERAL)
            }
        } catch (e: Exception) {
            Log.e("StandardTx", "FinalCommit error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }
}

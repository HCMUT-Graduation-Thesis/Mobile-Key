package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.Admin
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
 * Standard Transaction (Passive Mode) - Used when the Phone acts as an HCE tag (NFC).
 * Updated to support Hybrid Security Recovery (HSR) by ensuring full key rotation.
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
        isCarVerified = false
        isDeviceVerified = false
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleAuthInit(payload: ByteArray): LogicalResponse {
        return try {
            onLog("NFC STD: Initiating Security Recovery (Phase 1)")
            
            val startIndex = payload.indexOf(0x04.toByte())
            if (startIndex == -1 || payload.size - startIndex < 65) return LogicalResponse(Status.ERR_GENERAL)

            val moduleId = payload.sliceArray(0 until startIndex)
            val record = storageManager.getAllKeys().find { it.moduleID?.contentEquals(moduleId) == true }
                ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
            
            activeRecord = record
            val vehiclePKBytes = payload.sliceArray(startIndex until startIndex + 65)
            val vehicleEphemeralPK = HandshakeProtector.parseUncompressedPublicKey(vehiclePKBytes)

            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
            val salt = record.immobilizerToken ?: return LogicalResponse(Status.ERR_GENERAL)
            
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, vehicleEphemeralPK, salt, CryptoConstants.STD_SESSION_INFO
            )

            sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehicleEphemeralPK)
            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            val responseData = HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public) + appNonce!!
            LogicalResponse(Status.SUCCESS, responseData)
        } catch (e: Exception) {
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleMutualVerify(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
        val record = activeRecord ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
        
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decrypted)

            if (buffer.remaining() < CryptoConstants.ML_DSA_65_SIG_SIZE + 16) return LogicalResponse(Status.ERR_GENERAL)

            val vehicleSig = ByteArray(CryptoConstants.ML_DSA_65_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            if (!identityCrypto.verify(appNonce!!, vehicleSig, record.vehiclePublicKey!!)) {
                onLog("NFC Error: Vehicle identity mismatch")
                return LogicalResponse(Status.ERR_AUTH_FAIL)
            }
            
            isCarVerified = true
            val appSig = identityCrypto.sign(readerChallenge, record.devicePrivateKey!!)
            isDeviceVerified = true

            onLog("NFC STD: Identity Verified (Phase 2)")
            val encrypted = CryptoUtils.encryptAesGcm((record.core.keyID ?: ByteArray(8)) + appSig, sessionKey)
            LogicalResponse(Status.SUCCESS, encrypted)
        } catch (e: Exception) {
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleActionSync(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
        val responseData = byteArrayOf(Admin.STD_MSG_SYNC_OK)
        val encrypted = CryptoUtils.encryptAesGcm(responseData, sessionKey)
        return LogicalResponse(Status.SUCCESS, encrypted)
    }

    private fun handleFinalCommit(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_AUTH_FAIL)
        val record = activeRecord ?: return LogicalResponse(Status.ERR_GENERAL)
        
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size < 2) return LogicalResponse(Status.ERR_GENERAL)

            if (decrypted[0] == Admin.STD_EXEC_SUCCESS && decrypted[1] == Admin.STD_COMMIT_MARKER) {
                // EXECUTE KEY ROTATION
                val newFastKey = CryptoUtils.deriveSessionKey(
                    sharedSecret!!,
                    record.immobilizerToken!!,
                    CryptoConstants.FAST_KEY_REFRESH.toByteArray(),
                    32
                )
                
                storageManager.updateFastKeyAndCounter(record.core.keyID!!, newFastKey, 0)
                isComplete = true
                onLog("NFC Sync Success: Security Restored for BLE & NFC.")
                LogicalResponse(Status.SUCCESS)
            } else {
                LogicalResponse(Status.ERR_GENERAL)
            }
        } catch (e: Exception) {
            LogicalResponse(Status.ERR_GENERAL)
        }
    }
}

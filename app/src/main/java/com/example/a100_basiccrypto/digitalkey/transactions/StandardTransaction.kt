package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.AUTH_INIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.ACTION_SYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.FINAL_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.MUTUAL_VERIFY
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_MSG_SYNC_OK
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_EXEC_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_COMMIT_MARKER
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.SecureRandom

/**
 * Standard Transaction V1.3.0 Implementation - Updated for IPassiveTransport.
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
            AUTH_INIT -> handleAuthInit(frame.payload)
            MUTUAL_VERIFY -> handleMutualVerify(frame.payload)
            ACTION_SYNC -> ifFullAuth { handleActionSync(frame.payload) }
            FINAL_COMMIT -> ifFullAuth { handleFinalCommit(frame.payload) }
            else -> LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun ifFullAuth(action: () -> LogicalResponse): LogicalResponse {
        return if (isCarVerified && isDeviceVerified) action()
        else LogicalResponse(MSG_ERR_AUTH_FAIL)
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
            val startIndex = payload.indexOf(0x04.toByte())
            if (startIndex == -1 || payload.size - startIndex < 65) return LogicalResponse(MSG_ERR_GENERAL)

            val vehiclePKBytes = payload.sliceArray(startIndex until startIndex + 65)
            val vehicleEphemeralPK = HandshakeProtector.parseUncompressedPublicKey(vehiclePKBytes)

            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()

            val salt = passwordProvider().toByteArray()
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, vehicleEphemeralPK, salt, CryptoConstants.STD_SESSION_INFO
            )

            sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehicleEphemeralPK)
            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            val responseData = HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public) + appNonce!!
            LogicalResponse(MSG_GLOBAL_SUCCESS, responseData)
        } catch (e: Exception) {
            Log.e("StandardTx", "AuthInit error: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun handleMutualVerify(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(MSG_ERR_AUTH_FAIL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decrypted)

            if (buffer.remaining() < 16 + CryptoConstants.ML_DSA_65_SIG_SIZE + 16) return LogicalResponse(MSG_ERR_GENERAL)

            val moduleId = ByteArray(16).also { buffer.get(it) }
            val vehicleSig = ByteArray(CryptoConstants.ML_DSA_65_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            val record = storageManager.getAllKeys().find { it.core.moduleID?.contentEquals(moduleId) == true }
                ?: return LogicalResponse(MSG_ERR_AUTH_FAIL)

            val vehiclePK = record.core.vehiclePublicKey ?: return LogicalResponse(MSG_ERR_AUTH_FAIL)
            
            if (!identityCrypto.verify(appNonce!!, vehicleSig, vehiclePK)) {
                onLog("Error: Vehicle PQC Sig Invalid")
                return LogicalResponse(MSG_ERR_AUTH_FAIL)
            }
            
            isCarVerified = true
            activeRecord = record

            val deviceSK = record.devicePrivateKey ?: return LogicalResponse(MSG_ERR_GENERAL)
            val appSig = identityCrypto.sign(readerChallenge, deviceSK)
            
            isDeviceVerified = true
            onLog("STD: Mutual Auth Success")
            val encrypted = CryptoUtils.encryptAesGcm((record.core.keyID ?: ByteArray(8)) + appSig, sessionKey)
            LogicalResponse(MSG_GLOBAL_SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e("StandardTx", "MutualVerify error: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun handleActionSync(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(MSG_ERR_AUTH_FAIL)
        val secret = sharedSecret ?: return LogicalResponse(MSG_ERR_GENERAL)
        val record = activeRecord ?: return LogicalResponse(MSG_ERR_GENERAL)

        return try {
            val immotoken = record.core.immobilizerToken ?: return LogicalResponse(MSG_ERR_GENERAL)
            stagedFastKey = CryptoUtils.deriveSessionKey(secret, immotoken, CryptoConstants.FAST_KEY_REFRESH.toByteArray(), 32)
            stagedCounter = 0
            
            onLog("STD: Action Req received.")
            val responseData = byteArrayOf(STD_MSG_SYNC_OK, INS_UNLOCK)
            val encrypted = CryptoUtils.encryptAesGcm(responseData, sessionKey)
            LogicalResponse(MSG_GLOBAL_SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e("StandardTx", "ActionSync error: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }

    private fun handleFinalCommit(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(MSG_ERR_AUTH_FAIL)
        val record = activeRecord ?: return LogicalResponse(MSG_ERR_GENERAL)
        val newKey = stagedFastKey ?: return LogicalResponse(MSG_ERR_GENERAL)

        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size < 2) return LogicalResponse(MSG_ERR_GENERAL)

            val execResult = decrypted[0]
            val commitMarker = decrypted[1]

            if (execResult == STD_EXEC_SUCCESS && commitMarker == STD_COMMIT_MARKER) {
                storageManager.updateFastKeyAndCounter(record.core.keyID!!, newKey, stagedCounter)
                isComplete = true
                onLog("STD: Recovery Complete.")
                LogicalResponse(MSG_GLOBAL_SUCCESS)
            } else LogicalResponse(MSG_ERR_GENERAL)
        } catch (e: Exception) {
            Log.e("StandardTx", "FinalCommit error: ${e.message}")
            LogicalResponse(MSG_ERR_GENERAL)
        }
    }
}

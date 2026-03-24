package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.command.MessageConstants.AUTH_INIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.ACTION_SYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.FINAL_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.MUTUAL_VERIFY
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_MSG_SYNC_OK
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_EXEC_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_COMMIT_MARKER
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.SecureRandom

/**
 * Standard Transaction V1.3.0 Implementation.
 * Action-Driven Recovery & Atomic Commit using PQC.
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

    // Staging Area (RAM only)
    private var stagedFastKey: ByteArray? = null
    private var stagedCounter: Int = 0

    private var isCarVerified = false
    private var isDeviceVerified = false
    private var isComplete = false

    private val STD_HKDF_INFO = "STD_SESSION"
    private val FAST_KEY_REFRESH = "FAST_KEY_REFRESH"
    private val DILITHIUM3_SIG_SIZE = 3309

    // Helper to log bytes in Hex with truncation
    private fun logBytes(label: String, data: ByteArray?) {
        if (data == null) {
            Log.d("StandardTx", "$label: null")
            return
        }
        val hex = data.take(16).toByteArray().joinToString("") { "%02x".format(it) }
        Log.d("StandardTx", "$label: [$hex...] (Size: ${data.size})")
    }

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return when (frame.msgId) {
            AUTH_INIT -> handleAuthInit(frame.payload)
            MUTUAL_VERIFY -> handleMutualVerify(frame.payload)
            ACTION_SYNC -> ifFullAuth { handleActionSync(frame.payload) }
            FINAL_COMMIT -> ifFullAuth { handleFinalCommit(frame.payload) }
            else -> {
                Log.w("StandardTx", "Unknown Command Received: ${frame.msgId}")
                byteArrayOf(MSG_ERR_GENERAL)
            }
        }
    }

    private fun ifFullAuth(action: () -> ByteArray): ByteArray {
        return if (isCarVerified && isDeviceVerified) {
            action()
        } else {
            Log.e("StandardTx", "Auth failed: CarVerified=$isCarVerified, DeviceVerified=$isDeviceVerified")
            byteArrayOf(MSG_ERR_AUTH_FAIL)
        }
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
        Log.d("StandardTx", "V1.3.0 Session Reset")
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleAuthInit(payload: ByteArray): ByteArray {
        return try {
            onLog("STD: Phase 1 - Key Exchange")
            val startIndex = payload.indexOf(0x04.toByte())
            if (startIndex == -1 || payload.size - startIndex < 65) {
                Log.e("StandardTx", "AuthInit: Invalid Reader Public Key")
                return byteArrayOf(MSG_ERR_GENERAL)
            }

            val vehiclePKBytes = payload.sliceArray(startIndex until startIndex + 65)
            val vehicleEphemeralPK = HandshakeProtector.parseUncompressedPublicKey(vehiclePKBytes)

            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()

            val salt = passwordProvider().toByteArray()
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, vehicleEphemeralPK, salt, STD_HKDF_INFO
            )

            sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehicleEphemeralPK)
            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            logBytes("App PK (Identity)", identityCrypto.getPublicKey())
            logBytes("Generated AppNonce", appNonce)
            
            HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public) + appNonce!!
        } catch (e: Exception) {
            Log.e("StandardTx", "AuthInit exception: ${e.message}")
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleMutualVerify(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: run {
            Log.e("StandardTx", "MutualVerify: Session Key is null")
            return SW_DECRYPTION_FAILED
        }
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decrypted)

            if (buffer.remaining() < 16 + DILITHIUM3_SIG_SIZE + 16) {
                Log.e("StandardTx", "MutualVerify: Payload too short. Remaining: ${buffer.remaining()}")
                return byteArrayOf(MSG_ERR_GENERAL)
            }

            val moduleId = ByteArray(16).also { buffer.get(it) }
            val vehicleSig = ByteArray(DILITHIUM3_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            logBytes("Received ModuleID", moduleId)
            logBytes("Received Vehicle Signature", vehicleSig)
            logBytes("Received Reader Challenge", readerChallenge)
            logBytes("Current AppNonce (for verify)", appNonce)

            val record = storageManager.getAllKeys().find { it.core.moduleID?.contentEquals(moduleId) == true }
                ?: run {
                    Log.e("StandardTx", "MutualVerify: ModuleID not found in storage")
                    onLog("Error: ModuleID not found.")
                    return byteArrayOf(MSG_ERR_AUTH_FAIL)
                }

            val vehiclePK = record.core.vehiclePublicKey ?: run {
                Log.e("StandardTx", "MutualVerify: Vehicle Public Key not found in record")
                return byteArrayOf(MSG_ERR_AUTH_FAIL)
            }
            
            logBytes("Stored Vehicle PK", vehiclePK)
            
            if (!identityCrypto.verify(appNonce!!, vehicleSig, vehiclePK)) {
                Log.e("StandardTx", "MutualVerify: Vehicle PQC Signature Verification FAILED")
                onLog("Error: Vehicle PQC Sig Invalid")
                return byteArrayOf(MSG_ERR_AUTH_FAIL)
            }
            
            isCarVerified = true
            activeRecord = record

            val deviceSK = record.devicePrivateKey ?: run {
                Log.e("StandardTx", "MutualVerify: Device Private Key is null")
                return byteArrayOf(MSG_ERR_GENERAL)
            }
            
            val appSig = identityCrypto.sign(readerChallenge, deviceSK)
            if (appSig.isEmpty()) {
                Log.e("StandardTx", "MutualVerify: Signing reader challenge FAILED (empty signature)")
                return byteArrayOf(MSG_ERR_GENERAL)
            }
            
            logBytes("Generated App Sig", appSig)
            
            isDeviceVerified = true
            onLog("STD: Mutual Auth Success")
            CryptoUtils.encryptAesGcm((record.core.keyID ?: ByteArray(8)) + appSig, sessionKey)
        } catch (e: Exception) {
            Log.e("StandardTx", "MutualVerify exception: ${e.message}")
            e.printStackTrace()
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleActionSync(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        val secret = sharedSecret ?: return byteArrayOf(MSG_ERR_GENERAL)
        val record = activeRecord ?: return byteArrayOf(MSG_ERR_GENERAL)

        return try {
            onLog("STD: Phase 3 - Derive Fast Key & Sync")
            
            val immotoken = record.core.immobilizerToken ?: run {
                Log.e("StandardTx", "ActionSync: Immobilizer Token is null")
                return byteArrayOf(MSG_ERR_GENERAL)
            }
            
            stagedFastKey = CryptoUtils.deriveSessionKey(secret, immotoken, FAST_KEY_REFRESH.toByteArray(), 32)
            stagedCounter = 0
            
            onLog("STD: Action Req received. Proposing UNLOCK + Sync.")
            val response = byteArrayOf(STD_MSG_SYNC_OK, INS_UNLOCK)
            CryptoUtils.encryptAesGcm(response, sessionKey)
        } catch (e: Exception) {
            Log.e("StandardTx", "ActionSync exception: ${e.message}")
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleFinalCommit(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        val record = activeRecord ?: return byteArrayOf(MSG_ERR_GENERAL)
        val newKey = stagedFastKey ?: return byteArrayOf(MSG_ERR_GENERAL)

        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size < 2) {
                Log.e("StandardTx", "FinalCommit: Payload too short (${decrypted.size})")
                return byteArrayOf(MSG_ERR_GENERAL)
            }

            val execResult = decrypted[0]
            val commitMarker = decrypted[1]

            if (execResult == STD_EXEC_SUCCESS && commitMarker == STD_COMMIT_MARKER) {
                onLog("STD: Phase 4 - Reader Executed OK. Atomic Commit...")
                storageManager.updateFastKeyAndCounter(record.core.keyID!!, newKey, stagedCounter)
                isComplete = true
                onLog("STD: Recovery Complete. Transaction Finalized.")
                SW_SUCCESS
            } else {
                Log.e("StandardTx", "FinalCommit: Execution Failed at Reader. Result=$execResult, Marker=$commitMarker")
                onLog("STD: Execution Failed at Reader")
                byteArrayOf(MSG_ERR_GENERAL)
            }
        } catch (e: Exception) {
            Log.e("StandardTx", "FinalCommit exception: ${e.message}")
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }
}

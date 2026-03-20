package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.command.MessageConstants.AUTH_INIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.ACTION_SYNC
import com.example.a100_basiccrypto.shared.command.MessageConstants.FINAL_COMMIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.MUTUAL_VERIFY
import com.example.a100_basiccrypto.shared.command.MessageConstants.REVOKE_OWNER
import com.example.a100_basiccrypto.shared.command.MessageConstants.FACTORY_RESET
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_GLOBAL_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_MSG_SYNC_OK
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_EXEC_SUCCESS
import com.example.a100_basiccrypto.shared.command.MessageConstants.STD_COMMIT_MARKER
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

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
    private val FAST_KEY_INFO = "FAST_KEY_REFRESH"
    private val DILITHIUM3_SIG_SIZE = 3309

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return when (frame.msgId) {
            AUTH_INIT -> handleAuthInit(frame.payload)
            MUTUAL_VERIFY -> handleMutualVerify(frame.payload)
            ACTION_SYNC -> ifFullAuth { handleActionSync(frame.payload) }
            FINAL_COMMIT -> ifFullAuth { handleFinalCommit(frame.payload) }
            else -> byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun ifFullAuth(action: () -> ByteArray): ByteArray {
        return if (isCarVerified && isDeviceVerified) action() else byteArrayOf(MSG_ERR_AUTH_FAIL)
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
            if (startIndex == -1 || payload.size - startIndex < 65) return byteArrayOf(MSG_ERR_GENERAL)

            val vehiclePKBytes = payload.sliceArray(startIndex until startIndex + 65)
            val vehicleEphemeralPK = CryptoUtils.getPublicKeyFromHex(vehiclePKBytes.toHex())

            val kpg = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }
            ephemeralKeyPair = kpg.generateKeyPair()

            sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehicleEphemeralPK)
            val salt = passwordProvider().toByteArray()
            currentSessionKey = CryptoUtils.deriveSessionKey(sharedSecret!!, salt, STD_HKDF_INFO.toByteArray(), 32)

            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            val ecPubKey = ephemeralKeyPair!!.public as ECPublicKey
            byteArrayOf(0x04.toByte()) + ecPubKey.w.affineX.toByteArray().normalize(32) + 
                    ecPubKey.w.affineY.toByteArray().normalize(32) + appNonce!!
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleMutualVerify(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decrypted)

            if (buffer.remaining() < 16 + DILITHIUM3_SIG_SIZE + 16) return byteArrayOf(MSG_ERR_GENERAL)

            val moduleId = ByteArray(16).also { buffer.get(it) }
            val vehicleSig = ByteArray(DILITHIUM3_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            val record = storageManager.getAllKeys().find { it.core.moduleID?.contentEquals(moduleId) == true }
                ?: return byteArrayOf(MSG_ERR_AUTH_FAIL).also { onLog("Error: ModuleID not found.") }

            val vehiclePK = record.core.vehiclePublicKey ?: return byteArrayOf(MSG_ERR_AUTH_FAIL)
            if (!identityCrypto.verify(appNonce!!, vehicleSig, vehiclePK)) {
                onLog("Error: Vehicle PQC Sig Invalid")
                return byteArrayOf(MSG_ERR_AUTH_FAIL)
            }
            
            isCarVerified = true
            activeRecord = record

            val deviceSK = record.devicePrivateKey ?: return byteArrayOf(MSG_ERR_GENERAL)
            val appSig = identityCrypto.sign(readerChallenge, deviceSK)
            isDeviceVerified = true
            
            onLog("STD: Mutual Auth Success")
            CryptoUtils.encryptAesGcm((record.core.keyID ?: ByteArray(8)) + appSig, sessionKey)
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleActionSync(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        val secret = sharedSecret ?: return byteArrayOf(MSG_ERR_GENERAL)
        val record = activeRecord ?: return byteArrayOf(MSG_ERR_GENERAL)

        return try {
            onLog("STD: Phase 3 - Derive Fast Key & Sync")
            
            // 1. Derive new Fast Auth Key using HKDF (SharedSecret + ImmobilizerToken)
            val immotoken = record.core.immobilizerToken ?: return byteArrayOf(MSG_ERR_GENERAL)
            stagedFastKey = CryptoUtils.deriveSessionKey(secret, immotoken, FAST_KEY_INFO.toByteArray(), 32)
            stagedCounter = 0
            
            onLog("STD: Action Req received. Proposing UNLOCK + Sync.")
            
            // 2. Respond with Sync Success + Instruction (Unlock)
            val response = byteArrayOf(STD_MSG_SYNC_OK, INS_UNLOCK)
            CryptoUtils.encryptAesGcm(response, sessionKey)
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleFinalCommit(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        val record = activeRecord ?: return byteArrayOf(MSG_ERR_GENERAL)
        val newKey = stagedFastKey ?: return byteArrayOf(MSG_ERR_GENERAL)

        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size < 2) return byteArrayOf(MSG_ERR_GENERAL)

            val execResult = decrypted[0]
            val commitMarker = decrypted[1]

            if (execResult == STD_EXEC_SUCCESS && commitMarker == STD_COMMIT_MARKER) {
                onLog("STD: Phase 4 - Reader Executed OK. Atomic Commit...")
                
                // FINAL ATOMIC COMMIT: Save to persistent storage
                storageManager.updateFastKeyAndCounter(record.core.keyID!!, newKey, stagedCounter)
                
                isComplete = true
                onLog("STD: Recovery Complete. Transaction Finalized.")
                
                // Response 90 00
                SW_SUCCESS
            } else {
                onLog("STD: Execution Failed at Reader")
                byteArrayOf(MSG_ERR_GENERAL)
            }
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }
}

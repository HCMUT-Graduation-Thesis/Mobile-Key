package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.command.MessageConstants.AUTH_INIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.COMMIT_ACTION
import com.example.a100_basiccrypto.shared.command.MessageConstants.FACTORY_RESET
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.shared.command.MessageConstants.MUTUAL_VERIFY
import com.example.a100_basiccrypto.shared.command.MessageConstants.REVOKE_OWNER
import com.example.a100_basiccrypto.shared.command.MessageConstants.SYNC_DATA
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Standard Transaction Implementation (Admin Flow).
 */
class StandardTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    private var currentSessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var appNonce: ByteArray? = null
    private var activeRecord: DigitalKeyRecord? = null

    private var isCarVerified = false
    private var isDeviceVerified = false
    private var isComplete = false

    private val STD_HKDF_INFO = "STD_SESSION"
    private val DILITHIUM3_SIG_SIZE = 3309

    override fun processCommand(frame: LogicalFrame): ByteArray {
        Log.d("StandardTx", "Incoming: INS=${"%02X".format(frame.msgId)}")
        return when (frame.msgId) {
            AUTH_INIT -> handleAuthInit(frame.payload)
            MUTUAL_VERIFY -> handleMutualVerify(frame.payload)
            SYNC_DATA -> ifFullAuth { handleSyncData(frame.payload) }
            COMMIT_ACTION -> ifFullAuth { handleCommitAction(frame.payload) }
            else -> byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun ifFullAuth(action: () -> ByteArray): ByteArray {
        return if (isCarVerified && isDeviceVerified) action() else byteArrayOf(MSG_ERR_AUTH_FAIL)
    }

    override fun resetTransaction() {
        currentSessionKey = null
        ephemeralKeyPair = null
        appNonce = null
        activeRecord = null
        isCarVerified = false
        isDeviceVerified = false
        isComplete = false
        Log.d("StandardTx", "Session State Cleared")
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleAuthInit(payload: ByteArray): ByteArray {
        return try {
            onLog("STD: Phase 1 - Auth Init (Secure Channel)")
            val startIndex = payload.indexOf(0x04.toByte())
            if (startIndex == -1 || payload.size - startIndex < 65) return byteArrayOf(MSG_ERR_GENERAL)

            val vehiclePKBytes = payload.sliceArray(startIndex until startIndex + 65)
            val vehicleEphemeralPK = CryptoUtils.getPublicKeyFromHex(vehiclePKBytes.toHex())

            val kpg = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }
            val keyPair = kpg.generateKeyPair()
            ephemeralKeyPair = keyPair

            val sharedSecret = CryptoUtils.generateSharedSecret(keyPair.private, vehicleEphemeralPK)
            val salt = passwordProvider().toByteArray()
            currentSessionKey = CryptoUtils.deriveSessionKey(sharedSecret, salt, STD_HKDF_INFO.toByteArray(), 32)

            // App Challenge for Phase 2
            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            val ecPubKey = keyPair.public as ECPublicKey
            onLog("STD: Session Key derived.")
            
            byteArrayOf(0x04.toByte()) + ecPubKey.w.affineX.toByteArray().normalize(32) + 
                    ecPubKey.w.affineY.toByteArray().normalize(32) + appNonce!!
        } catch (e: Exception) {
            Log.e("StandardTx", "AuthInit Crash", e)
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleMutualVerify(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val buffer = ByteBuffer.wrap(decrypted)

            if (buffer.remaining() < 3341) return byteArrayOf(MSG_ERR_GENERAL)

            val moduleId = ByteArray(16).also { buffer.get(it) }
            val vehicleSig = ByteArray(DILITHIUM3_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            val contextNonce = appNonce ?: return byteArrayOf(MSG_ERR_GENERAL)
            val record = storageManager.getAllKeys().find { it.core.moduleID?.contentEquals(moduleId) == true }
                ?: return byteArrayOf(MSG_ERR_AUTH_FAIL).also { onLog("Error: ModuleID not found.") }

            // 1. Verify Reader (Vehicle)
            val vehiclePK = record.core.vehiclePublicKey ?: return byteArrayOf(MSG_ERR_AUTH_FAIL)
            val isVehicleValid = identityCrypto.verify(contextNonce, vehicleSig, vehiclePK)
            if (!isVehicleValid) {
                onLog("Error: Vehicle PQC Signature Invalid!")
                return byteArrayOf(MSG_ERR_AUTH_FAIL)
            }
            isCarVerified = true
            activeRecord = record

            // 2. Sign for Device (App)
            onLog("STD: Phase 2 - Vehicle Verified. Signing challenge...")
            val deviceSK = record.devicePrivateKey ?: return byteArrayOf(MSG_ERR_GENERAL)
            val appSig = identityCrypto.sign(readerChallenge, deviceSK)
            isDeviceVerified = true
            
            // Response: KeyID(8) + AppSignature(3309)
            CryptoUtils.encryptAesGcm((record.core.keyID ?: ByteArray(8)) + appSig, sessionKey)
        } catch (e: Exception) {
            Log.e("StandardTx", "MutualVerify Crash", e)
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleSyncData(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            onLog("STD: Phase 3 - Sync Data (Fast Key Update)")
            val newFastKey = ByteArray(32).apply { SecureRandom().nextBytes(this) }
            activeRecord?.let {
                it.core.fastAuthKey = newFastKey
                it.core.transactionCounter = 0 // Reset counter per spec
                storageManager.saveDigitalKey(it)
                onLog("Success: FastAuthKey rotated & Counter reset.")
            }
            CryptoUtils.encryptAesGcm(newFastKey, sessionKey)
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleCommitAction(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.isNotEmpty()) {
                val adminCmd = decrypted[0]
                onLog("STD: Phase 4 - Admin Command: ${"%02X".format(adminCmd)}")
                when (adminCmd) {
                    REVOKE_OWNER -> {
                        activeRecord?.let { storageManager.deleteKey(it.core.keyID!!) }
                        onLog("ADMIN: Key revoked and deleted.")
                    }
                    FACTORY_RESET -> {
                        storageManager.clearAll()
                        onLog("ADMIN: All keys cleared.")
                    }
                }
            } else {
                onLog("STD: Phase 5 - Final Commit.")
            }
            isComplete = true
            byteArrayOf(0x90.toByte(), 0x00.toByte())
        } catch (e: Exception) {
            Log.e("StandardTx", "Commit Crash", e)
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }
}

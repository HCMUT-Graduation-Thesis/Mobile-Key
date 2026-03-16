package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.AUTH_INIT
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.COMMIT_ACTION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.FACTORY_RESET
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_AUTH_FAIL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.MSG_ERR_GENERAL
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.REVOKE_OWNER
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.SYNC_DATA
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.VERIFY_CAR
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.VERIFY_DEVICE
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_DECRYPTION_FAILED
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Standard Transaction Implementation (Admin Flow).
 * Matches Reader implementation: [ModuleID(16) + VehicleSig(3309) + ReaderChallenge(16)] = 3341 bytes.
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
        Log.d("StandardTx", "Incoming: INS=${"%02X".format(frame.msgId)}, Size=${frame.payload.size}")
        return when (frame.msgId) {
            AUTH_INIT -> handleAuthInit(frame.payload)
            VERIFY_CAR -> handleVerifyCar(frame.payload)
            VERIFY_DEVICE -> handleVerifyDevice(frame.payload)
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
        Log.d("StandardTx", "State Reset")
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun logLargeString(tag: String, message: String) {
        val maxLogSize = 3000
        for (i in 0..message.length / maxLogSize) {
            val start = i * maxLogSize
            var end = (i + 1) * maxLogSize
            if (end > message.length) end = message.length
            Log.d(tag, "Part $i: " + message.substring(start, end))
        }
    }

    private fun handleAuthInit(payload: ByteArray): ByteArray {
        return try {
            onLog("STD: Phase 1 - Auth Init")
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

            appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            
            // Log AppNonce at the end of Phase 1 as requested
            Log.i("CryptoAudit", "==== PHASE 1 END ====")
            Log.i("CryptoAudit", "App Nonce Generated: ${appNonce?.toHex()}")
            Log.i("CryptoAudit", "=====================")
            
            val ecPubKey = keyPair.public as ECPublicKey
            
            onLog("STD: Secure Channel Established.")
            byteArrayOf(0x04.toByte()) + ecPubKey.w.affineX.toByteArray().normalize(32) + 
                    ecPubKey.w.affineY.toByteArray().normalize(32) + appNonce!!
        } catch (e: Exception) {
            Log.e("StandardTx", "AuthInit Crash", e)
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleVerifyCar(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Decrypted Payload: ${decrypted.size} bytes")
            
            val buffer = ByteBuffer.wrap(decrypted)

            // Structure: ModuleID(16) + VehicleSig(3309) + ReaderChallenge(16) = 3341
            if (buffer.remaining() < 3341) {
                Log.e("StandardTx", "Payload too short: ${buffer.remaining()}")
                return byteArrayOf(MSG_ERR_GENERAL)
            }

            val moduleId = ByteArray(16).also { buffer.get(it) }
            val vehicleSig = ByteArray(DILITHIUM3_SIG_SIZE).also { buffer.get(it) }
            val readerChallenge = ByteArray(16).also { buffer.get(it) }

            val contextNonce = appNonce ?: return byteArrayOf(MSG_ERR_GENERAL)
            
            val record = storageManager.getAllKeys().find { it.moduleID.contentEquals(moduleId) }
                ?: return byteArrayOf(MSG_ERR_AUTH_FAIL).also { onLog("Error: Record Missing") }

            val vehiclePK = record.vehiclePublicKey ?: return byteArrayOf(MSG_ERR_AUTH_FAIL)

            // --- DETAILED AUDIT LOGS ---
            Log.i("CryptoAudit", "==== PHASE 2: VERIFY CAR ====")
            Log.i("CryptoAudit", "ModuleID: ${moduleId.toHex()}")
            Log.i("CryptoAudit", "App Nonce (Context): ${contextNonce.toHex()}")
            logLargeString("CryptoAudit", "Vehicle Public Key: ${vehiclePK.toHex()}")
            logLargeString("CryptoAudit", "Vehicle Signature: ${vehicleSig.toHex()}")
            Log.i("CryptoAudit", "Reader Challenge (to be signed): ${readerChallenge.toHex()}")
            Log.i("CryptoAudit", "=============================")

            // Verification - Dilithium3 verification with context
            // Note: If Reader uses AppNonce as context, it must be passed here.
            // Current user feedback: "Reader also doesn't use context". 
            // So we use empty/default context.
            val isValid = identityCrypto.verify(contextNonce, vehicleSig, vehiclePK)
            if (!isValid) {
                onLog("Error: PQC Signature Invalid!")
                return byteArrayOf(MSG_ERR_AUTH_FAIL)
            }

            onLog("Vehicle Authenticated (PQC Valid).")
            activeRecord = record
            isCarVerified = true

            // MUTUAL AUTH: Sign the reader's challenge immediately
            val deviceSK = record.devicePrivateKey ?: return byteArrayOf(MSG_ERR_GENERAL)
            val appSig = identityCrypto.sign(readerChallenge, deviceSK)
            isDeviceVerified = true
            
            onLog("Device Signature generated and sent.")
            
            // Response: KeyID(8) + AppSignature(3309)
            CryptoUtils.encryptAesGcm(record.keyID!! + appSig, sessionKey)
        } catch (e: Exception) {
            Log.e("StandardTx", "VerifyCar Crash", e)
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleVerifyDevice(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            val challenge = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val record = activeRecord ?: return byteArrayOf(MSG_ERR_AUTH_FAIL)
            val deviceSK = record.devicePrivateKey ?: return byteArrayOf(MSG_ERR_GENERAL)
            val appSig = identityCrypto.sign(challenge, deviceSK)
            isDeviceVerified = true
            CryptoUtils.encryptAesGcm(record.keyID!! + appSig, sessionKey)
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }

    private fun handleSyncData(payload: ByteArray): ByteArray {
        val sessionKey = currentSessionKey ?: return SW_DECRYPTION_FAILED
        return try {
            onLog("STD: Phase 4 - Data Sync")
            val newFastKey = ByteArray(32).apply { SecureRandom().nextBytes(this) }
            activeRecord?.let {
                it.fastAuthKey = newFastKey
                it.transactionCounter = 0
                storageManager.saveDigitalKey(it)
                onLog("FastAuthKey updated.")
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
            if (decrypted.isEmpty()) return byteArrayOf(MSG_ERR_GENERAL)
            val adminCmd = decrypted[0]
            when (adminCmd) {
                REVOKE_OWNER -> {
                    activeRecord?.let { storageManager.deleteKey(it.keyID!!) }
                    onLog("ADMIN: Key Revoked.")
                }
                FACTORY_RESET -> {
                    storageManager.clearAll()
                    onLog("ADMIN: Reset.")
                }
                else -> onLog("STD: Committed.")
            }
            isComplete = true
            byteArrayOf(0x90.toByte(), 0x00.toByte())
        } catch (e: Exception) {
            byteArrayOf(MSG_ERR_GENERAL)
        }
    }
}

package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.physical.NfcConstants
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.interfaces.ECPublicKey

/**
 * Orchestrates the Friend Pairing logic (State Machine) for PQC Digital Key.
 * Uses ML-DSA 3 (Dilithium 3) for Identity and ECDH for Session Security.
 */
class FriendPairingTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val record: DigitalKeyRecord,
    private val pairingCode: String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    companion object {
        private const val TAG = "FriendPairingTrans"
        private const val FAST_AUTH_TAG = "DIGITAL_KEY_FAST_AUTH"
    }

    private var sessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var isComplete = false

    override fun processCommand(frame: LogicalFrame): ByteArray {
        return when (frame.msgId) {
            MessageConstants.PHASE_FRIEND_INIT -> handleInit()
            MessageConstants.PHASE_FRIEND_KEM -> handleEcdhExchange(frame.payload)
            MessageConstants.PHASE_VERIFY_ATTEST -> handleVerifyAttestation(frame.payload)
            MessageConstants.PHASE_FRIEND_POP -> handleProofOfPossession(frame.payload)
            MessageConstants.PHASE_FRIEND_PROV -> handleProvisioning(frame.payload)
            MessageConstants.PHASE_FRIEND_COMMIT -> handleCommit()
            else -> byteArrayOf(MessageConstants.MSG_ERR_GENERAL)
        }
    }

    override fun resetTransaction() {
        CryptoUtils.secureClear(sessionKey)
        sessionKey = null
        ephemeralKeyPair = null
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleInit(): ByteArray {
        onLog("Phase 1: Generating ECDH Ephemeral Key & Sending PK")
        return try {
            // 1. Generate ephemeral ECDH keypair for the App
            val keyPair = CryptoUtils.generateEcKeyPair()
            ephemeralKeyPair = keyPair

            // 2. Extract uncompressed Public Key (65 bytes)
            val ecPubKey = keyPair.public as ECPublicKey
            val x = CryptoUtils.run { ecPubKey.w.affineX.toByteArray().normalize(32) }
            val y = CryptoUtils.run { ecPubKey.w.affineY.toByteArray().normalize(32) }
            val pk = byteArrayOf(0x04.toByte()) + x + y

            // 3. Return PK + Success code
            pk + byteArrayOf(MessageConstants.MSG_GLOBAL_SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "Init error: ${e.message}")
            byteArrayOf(MessageConstants.MSG_ERR_GENERAL)
        }
    }

    private fun handleEcdhExchange(payload: ByteArray): ByteArray {
        onLog("Phase 2: Computing Shared Secret (ECDH)")
        return try {
            // 1. Receive Reader's Public Key from payload (65 bytes)
            val readerPK = CryptoUtils.getPublicKeyFromBytes(payload)
            val myPriv = ephemeralKeyPair?.private ?: throw IllegalStateException("Ephemeral key missing")

            // 2. Perform ECDH Key Agreement
            val sharedSecret = CryptoUtils.generateSharedSecret(myPriv, readerPK)

            // 3. Derive Session Key using HKDF
            val sKey = CryptoUtils.deriveSessionKey(
                ikm = sharedSecret,
                salt = "FRIEND_ECDH_SALT".toByteArray(),
                info = "FRIEND_SESSION_V1".toByteArray(),
                length = 32
            )
            sessionKey = sKey

            // LOG SESSION KEY FOR DEBUGGING
            Log.d(TAG, "SESSION_KEY (Phase 2): ${sKey.joinToString("") { "%02X".format(it) }}")
            onLog("System: Session Key established.")

            // 4. Release ephemeral keys
            ephemeralKeyPair = null
            byteArrayOf(MessageConstants.MSG_GLOBAL_SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "ECDH error: ${e.message}")
            byteArrayOf(MessageConstants.MSG_ERR_GENERAL)
        }
    }

    private fun handleVerifyAttestation(payload: ByteArray): ByteArray {
        val sKey = sessionKey ?: return NfcConstants.SW_DECRYPTION_FAILED
        return try {
            onLog("Phase 3.1: Sending Authorization (AP) & Identity PK")

            val identityPK = identityCrypto.getPublicKey()
            val ap = record.attestationPackage ?: return NfcConstants.SW_INTERNAL_ERROR

            val codeBytes = pairingCode.toByteArray().run {
                if (size < 32) this + ByteArray(32 - size) else this
            }

            val bundle = ByteBuffer.allocate(2 + ap.size + 2 + identityPK.size + 32).apply {
                putShort(ap.size.toShort())
                put(ap)
                putShort(identityPK.size.toShort())
                put(identityPK)
                put(codeBytes)
            }.array()

            // Append 0x90 at the end of encrypted packet for Reader logic consistency
            CryptoUtils.encryptAesGcm(bundle, sKey) + byteArrayOf(MessageConstants.MSG_GLOBAL_SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3.1 error: ${e.message}")
            NfcConstants.SW_INTERNAL_ERROR
        }
    }

    private fun handleProofOfPossession(payload: ByteArray): ByteArray {
        val sKey = sessionKey ?: return NfcConstants.SW_DECRYPTION_FAILED
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sKey)

            if (decrypted.size == 1 && decrypted[0] == MessageConstants.ERR_FRIEND_INVCODE_MISMATCH) {
                onLog("Error: Invitation Code mismatch on Vehicle")
                return byteArrayOf(MessageConstants.ERR_FRIEND_INVCODE_MISMATCH)
            }

            onLog("Phase 3.2: Signing Challenge Nonce (ML-DSA 3)")
            val signature = identityCrypto.sign(decrypted, identityCrypto.getPrivateKey())

            // Append 0x90 at the end of encrypted packet
            CryptoUtils.encryptAesGcm(signature, sKey) + byteArrayOf(MessageConstants.MSG_GLOBAL_SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3.2 error: ${e.message}")
            NfcConstants.SW_DECRYPTION_FAILED
        }
    }

    private fun handleProvisioning(payload: ByteArray): ByteArray {
        val sKey = sessionKey ?: return NfcConstants.SW_DECRYPTION_FAILED
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sKey)
            if (decrypted.size == 1 && decrypted[0] == MessageConstants.ERR_FRIEND_POP_FAILED) {
                onLog("Error: Identity proof failed on Vehicle")
                return byteArrayOf(MessageConstants.ERR_FRIEND_POP_FAILED)
            }

            onLog("Phase 4: Receiving Operational Data")
            val buffer = ByteBuffer.wrap(decrypted)

            record.apply {
                core.slotID = buffer.get()
                core.keyID = ByteArray(8).apply { buffer.get(this) }
                core.immobilizerToken = ByteArray(64).apply { buffer.get(this) }
                core.permissions = buffer.int

                core.fastAuthKey = CryptoUtils.deriveSessionKey(sKey, pairingCode.toByteArray(), FAST_AUTH_TAG.toByteArray(), 32)

                devicePrivateKey = identityCrypto.getPrivateKey()
                core.devicePublicKey = identityCrypto.getPublicKey()
                core.keyState = KeyState.PROVISIONING
            }

            storageManager.saveDigitalKey(record)
            byteArrayOf(MessageConstants.MSG_GLOBAL_SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "Phase 4 error: ${e.message}")
            NfcConstants.SW_DECRYPTION_FAILED
        }
    }

    private fun handleCommit(): ByteArray {
        record.core.keyState = KeyState.ACTIVE
        storageManager.saveDigitalKey(record)

        onLog("Phase 5: Pairing Successful. Friend Key is ACTIVE.")
        isComplete = true
        CryptoUtils.secureClear(sessionKey)
        sessionKey = null

        return byteArrayOf(MessageConstants.MSG_GLOBAL_SUCCESS)
    }
}

package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants.FriendPairing
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.physical.NfcConstants
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.interfaces.ECPublicKey

/**
 * Orchestrates the Friend Pairing logic - Updated for IPassiveTransport.
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
    }

    private var sessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var isComplete = false

    override fun processCommand(frame: LogicalFrame, transport: IPassiveTransport): LogicalResponse {
        return when (frame.msgId) {
            FriendPairing.PHASE_INIT -> handleInit()
            FriendPairing.PHASE_KEM_EXCHANGE -> handleEcdhExchange(frame.payload)
            FriendPairing.PHASE_VERIFY_ATTEST -> handleVerifyAttestation(frame.payload)
            FriendPairing.PHASE_SIGN_POP -> handleProofOfPossession(frame.payload)
            FriendPairing.PHASE_PROVISIONING -> handleProvisioning(frame.payload)
            FriendPairing.PHASE_COMMIT -> handleCommit()
            else -> LogicalResponse(Status.ERR_GENERAL)
        }
    }

    override fun resetTransaction() {
        CryptoUtils.secureClear(sessionKey)
        sessionKey = null
        ephemeralKeyPair = null
        isComplete = false
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleInit(): LogicalResponse {
        onLog("Phase 1: Generating ECDH Ephemeral Key")
        return try {
            val keyPair = CryptoUtils.generateEcKeyPair()
            ephemeralKeyPair = keyPair
            val ecPubKey = keyPair.public as ECPublicKey
            val x = CryptoUtils.run { ecPubKey.w.affineX.toByteArray().normalize(32) }
            val y = CryptoUtils.run { ecPubKey.w.affineY.toByteArray().normalize(32) }
            val pk = byteArrayOf(0x04.toByte()) + x + y
            LogicalResponse(Status.SUCCESS, pk)
        } catch (e: Exception) {
            Log.e(TAG, "Init error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleEcdhExchange(payload: ByteArray): LogicalResponse {
        onLog("Phase 2: Computing Shared Secret")
        return try {
            val readerPK = CryptoUtils.getPublicKeyFromBytes(payload)
            val myPriv = ephemeralKeyPair?.private ?: throw IllegalStateException("Key missing")
            val sharedSecret = CryptoUtils.generateSharedSecret(myPriv, readerPK)
            sessionKey = CryptoUtils.deriveSessionKey(
                ikm = sharedSecret,
                salt = CryptoConstants.FRIEND_ECDH_SALT.toByteArray(),
                info = CryptoConstants.FRIEND_SESSION_INFO.toByteArray(),
                length = 32
            )
            onLog("System: Session Key established.")
            ephemeralKeyPair = null
            LogicalResponse(Status.SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "ECDH error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleVerifyAttestation(payload: ByteArray): LogicalResponse {
        val sKey = sessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            onLog("Phase 3.1: Sending Authorization & Identity PK")
            val identityPK = identityCrypto.getPublicKey()
            val ap = record.attestationPackage ?: return LogicalResponse(Status.ERR_GENERAL)
            val codeBytes = pairingCode.toByteArray().run { if (size < 32) this + ByteArray(32 - size) else this }
            val bundle = ByteBuffer.allocate(2 + ap.size + 2 + identityPK.size + 32).apply {
                putShort(ap.size.toShort()); put(ap)
                putShort(identityPK.size.toShort()); put(identityPK)
                put(codeBytes)
            }.array()
            LogicalResponse(Status.SUCCESS, CryptoUtils.encryptAesGcm(bundle, sKey))
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3.1 error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleProofOfPossession(payload: ByteArray): LogicalResponse {
        val sKey = sessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sKey)
            if (decrypted.size == 1 && decrypted[0] == FriendPairing.ERR_INVCODE_MISMATCH) {
                onLog("Error: Invitation Code mismatch")
                return LogicalResponse(FriendPairing.ERR_INVCODE_MISMATCH)
            }
            onLog("Phase 3.2: Signing Challenge")
            val signature = identityCrypto.sign(decrypted, identityCrypto.getPrivateKey())
            LogicalResponse(Status.SUCCESS, CryptoUtils.encryptAesGcm(signature, sKey))
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3.2 error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleProvisioning(payload: ByteArray): LogicalResponse {
        val sKey = sessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sKey)
            if (decrypted.size == 1 && decrypted[0] == FriendPairing.ERR_POP_FAILED) {
                onLog("Error: Identity proof failed")
                return LogicalResponse(FriendPairing.ERR_POP_FAILED)
            }
            onLog("Phase 4: Receiving Data")
            val buffer = ByteBuffer.wrap(decrypted)
            record.apply {
                core.slotID = buffer.get()
                core.keyID = ByteArray(8).apply { buffer.get(this) }
                core.immobilizerToken = ByteArray(64).apply { buffer.get(this) }
                core.permissions = buffer.int
                core.fastAuthKey = CryptoUtils.deriveSessionKey(sKey, pairingCode.toByteArray(), CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32)
                devicePrivateKey = identityCrypto.getPrivateKey()
                devicePublicKey = identityCrypto.getPublicKey()
                core.keyState = KeyState.PROVISIONING
            }
            storageManager.saveDigitalKey(record)
            LogicalResponse(Status.SUCCESS)
        } catch (e: Exception) {
            Log.e(TAG, "Phase 4 error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleCommit(): LogicalResponse {
        record.core.keyState = KeyState.ACTIVE
        storageManager.saveDigitalKey(record)
        onLog("Phase 5: Pairing Successful.")
        isComplete = true
        CryptoUtils.secureClear(sessionKey); sessionKey = null
        return LogicalResponse(Status.SUCCESS)
    }
}

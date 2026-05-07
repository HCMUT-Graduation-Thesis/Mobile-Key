package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.FriendPairing
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.link.IActiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.model.KeyState
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.interfaces.ECPublicKey

/**
 * FriendPairingClient - Implements the 5-phase pairing flow for Friend/Guest over BLE.
 */
class FriendPairingClient(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "FriendPairingClient"
    }

    private var sessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null

    /**
     * Executes the full Friend Pairing flow over BLE.
     */
    suspend fun execute(transport: IActiveTransport, record: DigitalKeyRecord, pin: String): Boolean {
        try {
            onLog("BLE: Starting Friend Pairing...")

            // 1. PHASE 1: Handshake
            if (!performHandshake(transport)) return false

            // 2. PHASE 2: Authorization
            if (!performAuthorization(transport, record, pin)) return false

            // 3. PHASE 3: Proof of Possession
            if (!performProofOfPossession(transport)) return false

            // 4. PHASE 4: Provisioning (Data Sync)
            if (!performProvisioning(transport, record, pin)) return false

            // 5. PHASE 5: Commit
            return performCommit(transport, record)

        } catch (e: Exception) {
            onLog("BLE Pairing Error: ${e.message}")
            Log.e(TAG, "Pairing failed", e)
            return false
        } finally {
            clearSession()
        }
    }

    private suspend fun performHandshake(transport: IActiveTransport): Boolean {
        onLog("P1: Initializing ECDH Exchange...")
        val initFrame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_INIT, byteArrayOf())
        val initResponse = transport.exchange(initFrame)
        if (initResponse.status != Status.SUCCESS) return false

        val vehiclePK = CryptoUtils.getPublicKeyFromBytes(initResponse.data)

        ephemeralKeyPair = CryptoUtils.generateEcKeyPair()
        val appPK = ephemeralKeyPair!!.public as ECPublicKey
        val x = CryptoUtils.run { appPK.w.affineX.toByteArray().normalize(32) }
        val y = CryptoUtils.run { appPK.w.affineY.toByteArray().normalize(32) }
        val appPKBytes = byteArrayOf(0x04.toByte()) + x + y

        val exchangeFrame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_KEM_EXCHANGE, appPKBytes)
        val exchangeResponse = transport.exchange(exchangeFrame)
        if (exchangeResponse.status != Status.SUCCESS) return false

        val sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehiclePK)
        sessionKey = CryptoUtils.deriveSessionKey(
            ikm = sharedSecret,
            salt = CryptoConstants.FRIEND_ECDH_SALT.toByteArray(),
            info = CryptoConstants.FRIEND_SESSION_INFO.toByteArray(),
            length = 32
        )
        onLog("P1: Secure Session established.")
        return true
    }

    private suspend fun performAuthorization(transport: IActiveTransport, record: DigitalKeyRecord, pin: String): Boolean {
        onLog("P2: Uploading Authorization Package...")
        val sKey = sessionKey ?: return false
        val ap = record.attestationPackage ?: return false
        val identityPK = identityCrypto.getPublicKey()
        
        val pinBytes = pin.toByteArray().let { if (it.size < 32) it + ByteArray(32 - it.size) else it }

        val bundle = ByteBuffer.allocate(2 + ap.size + 2 + identityPK.size + 32).apply {
            putShort(ap.size.toShort())
            put(ap)
            putShort(identityPK.size.toShort())
            put(identityPK)
            put(pinBytes)
        }.array()

        val encryptedPayload = CryptoUtils.encryptAesGcm(bundle, sKey)
        val frame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_VERIFY_ATTEST, encryptedPayload)
        val response = transport.exchange(frame)
        if (response.status == FriendPairing.ERR_INVCODE_MISMATCH) {
            onLog("Error: Invalid PIN code according to vehicle.")
            return false
        }
        return response.status == Status.SUCCESS
    }

    private suspend fun performProofOfPossession(transport: IActiveTransport): Boolean {
        onLog("P3: Proving Identity Possession...")
        val sKey = sessionKey ?: return false

        // Request Challenge
        val reqFrame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_SIGN_POP, byteArrayOf())
        val response = transport.exchange(reqFrame)
        if (response.status != Status.SUCCESS) return false

        val challenge = CryptoUtils.decryptAesGcm(response.data, sKey)
        val signature = identityCrypto.sign(challenge, identityCrypto.getPrivateKey())
        val encryptedSig = CryptoUtils.encryptAesGcm(signature, sKey)
        val sigFrame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_SIGN_POP, encryptedSig)

        val sigResponse = transport.exchange(sigFrame)
        if (sigResponse.status == FriendPairing.ERR_POP_FAILED) {
            onLog("Error: Proof of Possession failed.")
            return false
        }
        return sigResponse.status == Status.SUCCESS
    }

    private suspend fun performProvisioning(transport: IActiveTransport, record: DigitalKeyRecord, pin: String): Boolean {
        onLog("P4: Receiving Provisioning Data...")
        val sKey = sessionKey ?: return false
        val frame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_PROVISIONING, byteArrayOf())
        val response = transport.exchange(frame)
        if (response.status != Status.SUCCESS) return false

        val decrypted = CryptoUtils.decryptAesGcm(response.data, sKey)
        val buffer = ByteBuffer.wrap(decrypted)
        
        // 1. Capture the temporary keyID (from AP) before it gets overwritten
        val temporaryKeyID = record.core.keyID?.copyOf()

        record.apply {
            core.slotID = buffer.get()
            // 2. Overwrite with the permanent keyID from vehicle
            core.keyID = ByteArray(8).apply { buffer.get(this) }
            immobilizerToken = ByteArray(64).apply { buffer.get(this) }
            core.permissions = buffer.int

            // Derive FastAuthKey for daily BLE usage
            core.fastAuthKey = CryptoUtils.deriveSessionKey(
                sKey, pin.toByteArray(), CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32
            )

            // Store our identity keys
            devicePrivateKey = identityCrypto.getPrivateKey()
            devicePublicKey = identityCrypto.getPublicKey()
            core.keyState = KeyState.PROVISIONING
        }

        // 3. Nếu KeyID thay đổi, thực hiện xóa bản ghi tạm thời cũ
        if (temporaryKeyID != null && !temporaryKeyID.contentEquals(record.core.keyID)) {
            Log.i(TAG, "🎯 Cleaning up temporary record: ${temporaryKeyID.toHex()}")
            storageManager.deleteKey(temporaryKeyID)
        }

        // 4. Lưu bản ghi chính thức
        storageManager.saveDigitalKey(record)
        return true
    }

    private suspend fun performCommit(transport: IActiveTransport, record: DigitalKeyRecord): Boolean {
        onLog("P5: Finalizing Pairing...")
        val frame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_COMMIT, byteArrayOf())
        val response = transport.exchange(frame)

        if (response.status == Status.SUCCESS) {
            record.core.keyState = KeyState.ACTIVE
            storageManager.saveDigitalKey(record)
            onLog("Pairing Successful! Key is now ACTIVE.")
            return true
        }
        return false
    }

    private fun clearSession() {
        CryptoUtils.secureClear(sessionKey)
        sessionKey = null
        ephemeralKeyPair = null
    }
}

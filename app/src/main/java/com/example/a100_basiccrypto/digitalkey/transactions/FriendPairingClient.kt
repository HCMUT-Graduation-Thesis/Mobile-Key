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
 * Updated: Complete data exchange in Phase 4 to match Owner Pairing standards.
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

            if (!performHandshake(transport)) return false
            if (!performAuthorization(transport, record, pin)) return false
            if (!performProofOfPossession(transport)) return false
            if (!performProvisioning(transport, record, pin)) return false
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
        onLog("P1: Handshake...")
        val initFrame = LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_INIT, byteArrayOf())
        val initResponse = transport.exchange(initFrame)
        if (initResponse.status != Status.SUCCESS) return false

        val vehiclePK = CryptoUtils.getPublicKeyFromBytes(initResponse.data)
        ephemeralKeyPair = CryptoUtils.generateEcKeyPair()
        val appPK = ephemeralKeyPair!!.public as ECPublicKey
        val x = CryptoUtils.run { appPK.w.affineX.toByteArray().normalize(32) }
        val y = CryptoUtils.run { appPK.w.affineY.toByteArray().normalize(32) }
        val appPKBytes = byteArrayOf(0x04.toByte()) + x + y

        val exchangeResponse = transport.exchange(LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_KEM_EXCHANGE, appPKBytes))
        if (exchangeResponse.status != Status.SUCCESS) return false

        val sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehiclePK)
        sessionKey = CryptoUtils.deriveSessionKey(sharedSecret, CryptoConstants.FRIEND_ECDH_SALT.toByteArray(), CryptoConstants.FRIEND_SESSION_INFO.toByteArray(), 32)
        return true
    }

    private suspend fun performAuthorization(transport: IActiveTransport, record: DigitalKeyRecord, pin: String): Boolean {
        onLog("P2: Authorization...")
        val sKey = sessionKey ?: return false
        val ap = record.attestationPackage ?: return false
        val identityPK = identityCrypto.getPublicKey()
        val pinBytes = pin.toByteArray().let { if (it.size < 32) it + ByteArray(32 - it.size) else it }

        val bundle = ByteBuffer.allocate(2 + ap.size + 2 + identityPK.size + 32).apply {
            putShort(ap.size.toShort()); put(ap)
            putShort(identityPK.size.toShort()); put(identityPK)
            put(pinBytes)
        }.array()

        val response = transport.exchange(LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_VERIFY_ATTEST, CryptoUtils.encryptAesGcm(bundle, sKey)))
        return response.status == Status.SUCCESS
    }

    private suspend fun performProofOfPossession(transport: IActiveTransport): Boolean {
        onLog("P3: Proof of Identity...")
        val sKey = sessionKey ?: return false
        val response = transport.exchange(LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_SIGN_POP, byteArrayOf()))
        if (response.status != Status.SUCCESS) return false

        val challenge = CryptoUtils.decryptAesGcm(response.data, sKey)
        val signature = identityCrypto.sign(challenge, identityCrypto.getPrivateKey())
        val sigResponse = transport.exchange(LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_SIGN_POP, CryptoUtils.encryptAesGcm(signature, sKey)))
        return sigResponse.status == Status.SUCCESS
    }

    /**
     * P4: Receiving Provisioning Data.
     * UPDATED: Aligned with Owner Pairing to receive Vehicle Identity PK and ModuleID.
     */
    private suspend fun performProvisioning(transport: IActiveTransport, record: DigitalKeyRecord, pin: String): Boolean {
        onLog("P4: Syncing Security Data...")
        val sKey = sessionKey ?: return false
        val response = transport.exchange(LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_PROVISIONING, byteArrayOf()))
        if (response.status != Status.SUCCESS) return false

        val decrypted = CryptoUtils.decryptAesGcm(response.data, sKey)
        val buffer = ByteBuffer.wrap(decrypted)
        
        val temporaryKeyID = record.core.keyID?.copyOf()

        record.apply {
            // 1. Vehicle Identity (Crucial for Standard Transactions)
            vehiclePublicKey = ByteArray(CryptoConstants.ML_DSA_65_PK_SIZE).apply { buffer.get(this) }
            
            // 2. Identifiers
            core.keyID = ByteArray(8).apply { buffer.get(this) }
            val receivedMID = ByteArray(16).apply { buffer.get(this) }
            
            // VERIFY: Ensure we are pairing with the correct vehicle from the invitation
            if (moduleID != null && !moduleID!!.contentEquals(receivedMID)) {
                Log.e(TAG, "Security Alert: ModuleID mismatch! Possible relay attack.")
                return false
            }
            moduleID = receivedMID

            // 3. Operational Data
            core.slotID = buffer.get()
            core.transactionCounter = buffer.int
            core.permissions = buffer.int
            immobilizerToken = ByteArray(64).apply { buffer.get(this) }
            
            // 4. Secrets
            core.fastAuthKey = CryptoUtils.deriveSessionKey(sKey, pin.toByteArray(), CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32)
            devicePrivateKey = identityCrypto.getPrivateKey()
            devicePublicKey = identityCrypto.getPublicKey()
            
            core.keyState = KeyState.PROVISIONING
        }

        if (temporaryKeyID != null && !temporaryKeyID.contentEquals(record.core.keyID)) {
            storageManager.deleteKey(temporaryKeyID)
        }

        storageManager.saveDigitalKey(record)
        return true
    }

    private suspend fun performCommit(transport: IActiveTransport, record: DigitalKeyRecord): Boolean {
        onLog("P5: Activating Key...")
        val response = transport.exchange(LogicalFrame(Class.FRIEND_PAIRING, FriendPairing.PHASE_COMMIT, byteArrayOf()))
        if (response.status == Status.SUCCESS) {
            record.core.keyState = KeyState.ACTIVE
            storageManager.saveDigitalKey(record)
            onLog("Success: Friend key is now ACTIVE.")
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

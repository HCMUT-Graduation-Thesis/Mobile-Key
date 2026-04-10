package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants.Admin
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.*
import com.example.a100_basiccrypto.shared.link.IActiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.SecureRandom

/**
 * StandardTransactionClient - Manages the complex 4-phase synchronization flow over BLE.
 * Optimized: KeyID is sent in Phase 1 only. Phase 2 sends only the PQC Signature.
 */
class StandardTransactionClient(
    private val storageManager: IKeyStorageManager,
    private val identityCrypto: IIdentityCrypto,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "StandardTxClient"
    }

    private var sessionKey: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var appNonce: ByteArray? = null

    /**
     * Executes the full Standard Transaction flow to synchronize keys and counters.
     */
    suspend fun executeSync(transport: IActiveTransport, keyID: ByteArray): Boolean {
        try {
            onLog("BLE: Starting Standard Transaction (Sync)...")
            
            // 1. PHASE 1: Key Exchange & Session Derivation
            val record = storageManager.getDigitalKey(keyID) ?: return false
            if (!performPhase1(transport, record)) return false
            
            // 2. PHASE 2: Mutual Identity Verification (PQC)
            if (!performPhase2(transport, record)) return false
            
            // 3. PHASE 3: Action Synchronization
            if (!performPhase3(transport)) return false
            
            // 4. PHASE 4: Atomic Commit & Persistence
            return performPhase4(transport, record)

        } catch (e: Exception) {
            onLog("BLE Standard Error: ${e.message}")
            return false
        } finally {
            clearSession()
        }
    }

    private suspend fun performPhase1(transport: IActiveTransport, record: DigitalKeyRecord): Boolean {
        // App initiates Auth Init with KeyID so Vehicle can identify the device and Salt
        val keyID = record.core.keyID ?: return false
        val initFrame = LogicalFrame(Class.ADMIN, Admin.PHASE_AUTH_INIT, keyID)
        
        val response = transport.exchange(initFrame)
        if (response.status != Status.SUCCESS) return false

        // Parse: [ModuleID (16B)] + [VehiclePubKey (65B)]
        val payload = response.data
        if (payload.size < 16 + 65) return false
        
        val vehiclePKBytes = payload.sliceArray(16 until 16 + 65)
        val vehicleEphemeralPK = HandshakeProtector.parseUncompressedPublicKey(vehiclePKBytes)
        
        ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
        val salt = record.immobilizerToken ?: return false
        
        sessionKey = HandshakeProtector.deriveSessionKey(
            ephemeralKeyPair!!.private, vehicleEphemeralPK, salt, CryptoConstants.STD_SESSION_INFO
        )
        sharedSecret = CryptoUtils.generateSharedSecret(ephemeralKeyPair!!.private, vehicleEphemeralPK)
        appNonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }

        return true
    }

    private suspend fun performPhase2(transport: IActiveTransport, record: DigitalKeyRecord): Boolean {
        // Step 2.1: Send App PK + Nonce to Vehicle (Plaintext)
        val appPKBytes = HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public)
        val phase2Payload = appPKBytes + appNonce!!
        
        val frame = LogicalFrame(Class.ADMIN, Admin.PHASE_MUTUAL_VERIFY, phase2Payload)
        val response = transport.exchange(frame)
        if (response.status != Status.SUCCESS) return false

        // Step 2.2: Decrypt Vehicle Signature: [VehicleSig (3309B)] + [VehicleChallenge (16B)]
        val decrypted = CryptoUtils.decryptAesGcm(response.data, sessionKey!!)
        val buffer = ByteBuffer.wrap(decrypted)
        
        val vehicleSig = ByteArray(CryptoConstants.ML_DSA_65_SIG_SIZE).also { buffer.get(it) }
        val vehicleChallenge = ByteArray(16).also { buffer.get(it) }

        // Verify Vehicle Identity
        val vehiclePK = record.vehiclePublicKey ?: return false
        if (!identityCrypto.verify(appNonce!!, vehicleSig, vehiclePK)) {
            onLog("BLE Error: Vehicle identity verification failed")
            return false
        }

        // Create App Signature on Vehicle's Challenge
        val deviceSK = record.devicePrivateKey ?: return false
        val appSig = identityCrypto.sign(vehicleChallenge, deviceSK)
        
        // Step 2.3: Finalize Phase 2 by sending ONLY App Sig (Encrypted)
        // KeyID is removed here as it was already provided in Phase 1
        val encryptedAuth = CryptoUtils.encryptAesGcm(appSig, sessionKey!!)
        
        val authFrame = LogicalFrame(Class.ADMIN, Admin.PHASE_MUTUAL_VERIFY, encryptedAuth)
        val authResponse = transport.exchange(authFrame)
        
        return authResponse.status == Status.SUCCESS
    }

    private suspend fun performPhase3(transport: IActiveTransport): Boolean {
        // App sends Sync Request
        val frame = LogicalFrame(Class.ADMIN, Admin.PHASE_ACTION_SYNC, byteArrayOf())
        val response = transport.exchange(frame)
        return response.status == Status.SUCCESS
    }

    private suspend fun performPhase4(transport: IActiveTransport, record: DigitalKeyRecord): Boolean {
        // App sends Commit Signal
        val commitPayload = byteArrayOf(Admin.STD_MSG_SYNC_OK)
        val encryptedCommit = CryptoUtils.encryptAesGcm(commitPayload, sessionKey!!)
        
        val frame = LogicalFrame(Class.ADMIN, Admin.PHASE_FINAL_COMMIT, encryptedCommit)
        val response = transport.exchange(frame)
        if (response.status != Status.SUCCESS) return false

        // Decrypt Final Marker: [ExecSuccess] + [CommitMarker]
        val decrypted = CryptoUtils.decryptAesGcm(response.data, sessionKey!!)
        if (decrypted.size >= 2 && 
            decrypted[0] == Admin.STD_EXEC_SUCCESS && 
            decrypted[1] == Admin.STD_COMMIT_MARKER) {
            
            // ROTATE FAST AUTH KEY
            val newFastKey = CryptoUtils.deriveSessionKey(
                sharedSecret!!,
                record.immobilizerToken!!,
                CryptoConstants.FAST_KEY_REFRESH.toByteArray(),
                32
            )
            
            storageManager.updateFastKeyAndCounter(record.core.keyID!!, newFastKey, 0)
            onLog("BLE Sync Success: Fast Auth Key rotated, Counter reset to 0.")
            return true
        }
        
        return false
    }

    private fun clearSession() {
        CryptoUtils.secureClear(sessionKey)
        CryptoUtils.secureClear(sharedSecret)
        sessionKey = null
        sharedSecret = null
        ephemeralKeyPair = null
        appNonce = null
    }
}

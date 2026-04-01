package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.link.IPassiveTransport
import com.example.a100_basiccrypto.shared.command.MessageConstants.OwnerPairing
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.HandshakeProtector
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.storage.BleIdentityManager
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.security.KeyPair

/**
 * Owner Pairing Transaction - Updated for Full Two-Way BLE OOB Exchange using persistent identity.
 */
class OwnerPairingTransaction(
    private val identityCrypto: IIdentityCrypto,
    private val storageManager: IKeyStorageManager,
    private val bleIdentityManager: BleIdentityManager,
    private val passwordProvider: () -> String,
    private val onLog: (String) -> Unit
) : ITransactionHandler {

    companion object {
        private const val TAG = "OwnerPairing"
    }

    private var currentSessionKey: ByteArray? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var isComplete = false
    private var pendingRecord: DigitalKeyRecord? = null
    
    private val gson = Gson()

    override fun processCommand(frame: LogicalFrame, transport: IPassiveTransport): LogicalResponse {
        return when (frame.msgId) {
            OwnerPairing.PHASE_REQ -> handleStartPairing()
            OwnerPairing.PHASE_KEY_EXCHANGE -> handleExchangePubKey(frame.payload)
            OwnerPairing.PHASE_VERIFY_NONCE -> handleVerifyNonce(frame.payload)
            OwnerPairing.PHASE_DATA_SYNC -> handleExchangeVehicleData(frame.payload)
            OwnerPairing.PHASE_COMMIT -> handleCommitPairing(frame.payload)
            else -> LogicalResponse(Status.ERR_GENERAL)
        }
    }

    override fun resetTransaction() {
        currentSessionKey = null
        ephemeralKeyPair = null
        isComplete = false
        pendingRecord = null
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleStartPairing(): LogicalResponse {
        onLog("Phase 1: Pairing Request Received")
        return LogicalResponse(Status.SUCCESS)
    }

    private fun handleExchangePubKey(payload: ByteArray): LogicalResponse {
        return try {
            onLog("Phase 2.a: Key Exchange")
            val pubKeyReaderBytes = payload.sliceArray(0 until 65)
            val pubKeyReader = HandshakeProtector.parseUncompressedPublicKey(pubKeyReaderBytes)

            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
            
            val salt = passwordProvider().toByteArray()
            currentSessionKey = HandshakeProtector.deriveSessionKey(
                ephemeralKeyPair!!.private, pubKeyReader, salt, CryptoConstants.OWNER_SESSION_INFO
            )

            onLog("Phase 2.a: Session Key established")
            val responseData = HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public)
            LogicalResponse(Status.SUCCESS, responseData)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 2a: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleVerifyNonce(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted2b = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 2.b: Nonce verified")
            
            val hcePubKey = identityCrypto.getPublicKey()
            val responseData = decrypted2b.sliceArray(0 until 16) + hcePubKey
            val encrypted = CryptoUtils.encryptAesGcm(responseData, sessionKey)
            LogicalResponse(Status.SUCCESS, encrypted)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 2b: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleExchangeVehicleData(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 3: Data Received from Vehicle")
            
            val buffer = ByteBuffer.wrap(decryptedData)
            val record = DigitalKeyRecord()

            // 1. Core Cryptographic Data (Vehicle PK)
            if (buffer.remaining() >= CryptoConstants.ML_DSA_65_PK_SIZE) {
                val vehiclePK = ByteArray(CryptoConstants.ML_DSA_65_PK_SIZE)
                buffer.get(vehiclePK)
                record.core.vehiclePublicKey = vehiclePK
            } else return LogicalResponse(Status.ERR_GENERAL)

            if (buffer.remaining() >= 8) {
                val kid = ByteArray(8)
                buffer.get(kid)
                record.core.keyID = kid
            }

            // 2. Hardware Identifiers
            if (buffer.remaining() >= 17) {
                val mid = ByteArray(16)
                buffer.get(mid)
                record.core.moduleID = mid
                record.core.slotID = buffer.get()
            }

            // 3. Permissions & Counters
            if (buffer.remaining() >= 8) {
                record.core.transactionCounter = buffer.int
                record.core.permissions = buffer.int
            }

            // 4. Validity
            if (buffer.remaining() >= 16) {
                record.core.validityStart = buffer.long
                record.core.validityEnd = buffer.long
            }

            // 5. Immobilizer Token
            if (buffer.remaining() >= 64) {
                val token = ByteArray(64)
                buffer.get(token)
                record.core.immobilizerToken = token
            }

            // 6. BLE OOB Data (Vehicle -> App)
            if (buffer.remaining() >= CryptoConstants.BLE_ADDR_SIZE) {
                val bleAddr = ByteArray(CryptoConstants.BLE_ADDR_SIZE)
                buffer.get(bleAddr)
                record.core.bleAddress = bleAddr
                onLog("Phase 3: Vehicle BLE Address received")
            }

            if (buffer.remaining() >= CryptoConstants.BLE_IRK_SIZE) {
                val irk = ByteArray(CryptoConstants.BLE_IRK_SIZE)
                buffer.get(irk)
                record.core.irk = irk
                onLog("Phase 3: Vehicle BLE IRK received")
            }

            // 7. Metadata (Remaining buffer)
            val metadataBytesLeft = buffer.remaining()
            if (metadataBytesLeft > 0) {
                val metadataBytes = ByteArray(metadataBytesLeft)
                buffer.get(metadataBytes)
                val metadataStr = String(metadataBytes, Charsets.UTF_8).trim { it <= ' ' }
                try {
                    if (metadataStr.isNotEmpty()) {
                        record.core.carMetadata = gson.fromJson(metadataStr, CarMetadata::class.java)
                        record.friendlyName = record.core.carMetadata?.modelName ?: "My Vehicle"
                    }
                } catch (e: Exception) { Log.e(TAG, "Metadata error: ${e.message}") }
            }

            // 8. Key Derivations (Fast Auth & BLE LTK)
            val salt = passwordProvider().toByteArray()
            
            // Derive Fast Auth Key (AES-256)
            record.core.fastAuthKey = CryptoUtils.deriveSessionKey(
                sessionKey, salt, CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32
            )
            
            // Derive BLE LTK (AES-128) - Shared between App and Vehicle
            record.core.bleLtk = CryptoUtils.deriveSessionKey(
                sessionKey, salt, CryptoConstants.BLE_LTK_INFO.toByteArray(), CryptoConstants.BLE_LTK_SIZE
            )
            onLog("Phase 3: BLE LTK derived successfully")

            record.devicePrivateKey = identityCrypto.getPrivateKey()
            record.core.devicePublicKey = identityCrypto.getPublicKey()
            
            record.core.keyState = KeyState.PROVISIONING
            pendingRecord = record
            storageManager.saveDigitalKey(record)
            
            // 9. Prepare Response Data (App -> Vehicle)
            // We send [Device PK | App BLE Address | App IRK]
            onLog("Phase 3: Sending App Identity & BLE OOB to Vehicle")
            
            val appBleAddress = bleIdentityManager.getAppBleAddress()
            val appIrk = bleIdentityManager.getAppIrk()

            val devicePubKey = record.core.devicePublicKey!!
            val responsePayload = ByteBuffer.allocate(
                devicePubKey.size + CryptoConstants.BLE_ADDR_SIZE + CryptoConstants.BLE_IRK_SIZE
            ).apply {
                put(devicePubKey)
                put(appBleAddress)
                put(appIrk)
            }.array()

            val encryptedResponse = CryptoUtils.encryptAesGcm(responsePayload, sessionKey)
            
            onLog("Phase 3 Complete. Key saved and OOB sent.")
            LogicalResponse(Status.SUCCESS, encryptedResponse)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 3: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleCommitPairing(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decryptedData.size == 1 && decryptedData[0] == 0x01.toByte()) {
                val recordToActivate = pendingRecord ?: storageManager.getAllKeys().lastOrNull { it.core.keyState == KeyState.PROVISIONING }
                if (recordToActivate != null) {
                    recordToActivate.core.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(recordToActivate)
                    onLog("Phase 4: Pairing Complete! Key is ACTIVE")
                    isComplete = true
                    LogicalResponse(Status.SUCCESS)
                } else LogicalResponse(Status.ERR_GENERAL)
            } else LogicalResponse(Status.ERR_GENERAL)
        } catch (e: Exception) {
            Log.e(TAG, "Error Phase 4: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }
}

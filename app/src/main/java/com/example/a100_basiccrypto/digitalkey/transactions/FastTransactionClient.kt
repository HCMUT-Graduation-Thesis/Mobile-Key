package com.example.a100_basiccrypto.digitalkey.transactions

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.CryptoConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.VehicleStatus
import com.example.a100_basiccrypto.shared.model.DoorLocation
import com.example.a100_basiccrypto.shared.model.DoorState
import com.example.a100_basiccrypto.shared.model.EngineState
import com.example.a100_basiccrypto.shared.model.TrunkState
import com.example.a100_basiccrypto.shared.link.IActiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import java.nio.ByteBuffer

/**
 * FastTransactionClient - Handles ACTIVE (Initiator) flow for BLE transactions.
 * Updated to return Byte status for Hybrid Security Recovery support.
 */
class FastTransactionClient(
    private val storageManager: IKeyStorageManager,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "FastTxClient"
    }

    /**
     * Executes control actions and returns the Status code from Vehicle.
     */
    suspend fun execute(
        transport: IActiveTransport,
        keyID: ByteArray,
        msgClass: Byte,
        targetIns: Byte
    ): Byte {
        try {
            val record = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(keyID) == true }
                ?: return Status.ERR_GENERAL

            val nextCounter = record.core.transactionCounter + 1
            storageManager.updateTransactionCounter(keyID, nextCounter)
            record.core.transactionCounter = nextCounter

            val authPayload = prepareActionRequest(record, targetIns, nextCounter) ?: return Status.ERR_GENERAL
            val frame = LogicalFrame(msgClass, targetIns, authPayload)
            val response = transport.exchange(frame)

            if (response.status == Status.SUCCESS) {
                val verified = verifyCommitMarker(record, response.data)
                return if (verified) Status.SUCCESS else Status.ERR_AUTH_FAIL
            }
            return response.status
        } catch (e: Exception) {
            onLog("BLE Fast Error: ${e.message}")
            return Status.ERR_GENERAL
        }
    }

    /**
     * Background Telemetry Sync - Uses BIG_ENDIAN for payload parsing.
     */
    suspend fun syncTelemetry(transport: IActiveTransport, keyID: ByteArray): VehicleStatus? {
        try {
            val record = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(keyID) == true }
                ?: return null

            val nextCounter = record.core.transactionCounter + 1
            storageManager.updateTransactionCounter(keyID, nextCounter)
            
            val authPayload = prepareActionRequest(record, Fast.INS_GET_ALL_TELEMETRY, nextCounter) ?: return null
            val frame = LogicalFrame(Class.TELEMETRY, Fast.INS_GET_ALL_TELEMETRY, authPayload)
            
            val response = transport.exchange(frame)
            if (response.status != Status.SUCCESS) return null

            val fastAuthKey = record.core.fastAuthKey ?: return null
            val decrypted = CryptoUtils.decryptAesGcm(response.data, fastAuthKey)
            
            val status = parseVehicleStatus(decrypted)

            Log.d(TAG, "Telemetry Received: Engine=${status.engineState}, Battery=${status.batteryLevel}%")
            storageManager.updateVehicleStatus(keyID, status)
            return status
        } catch (e: Exception) {
            onLog("Telemetry Sync Error: ${e.message}")
            return null
        }
    }

    private fun parseVehicleStatus(data: ByteArray): VehicleStatus {
        val buffer = ByteBuffer.wrap(data)
        val doorMask = buffer.get().toInt()
        val engineByte = buffer.get().toInt()
        val trunkByte = buffer.get().toInt()
        
        return VehicleStatus(
            doorStates = mapOf(
                DoorLocation.FRONT_LEFT to if (doorMask and 0x01 != 0) DoorState.LOCKED else DoorState.UNLOCKED,
                DoorLocation.FRONT_RIGHT to if (doorMask and 0x02 != 0) DoorState.LOCKED else DoorState.UNLOCKED,
                DoorLocation.REAR_LEFT to if (doorMask and 0x04 != 0) DoorState.LOCKED else DoorState.UNLOCKED,
                DoorLocation.REAR_RIGHT to if (doorMask and 0x08 != 0) DoorState.LOCKED else DoorState.UNLOCKED
            ),
            engineState = if (engineByte == 1) EngineState.RUNNING else EngineState.STOPPED,
            trunkState = if (trunkByte == 1) TrunkState.OPEN else TrunkState.CLOSED,
            temperature = buffer.float,
            batteryLevel = buffer.int,
            odometer = buffer.double
        )
    }

    private fun prepareActionRequest(record: DigitalKeyRecord, targetIns: Byte, counter: Int): ByteArray? {
        try {
            if (record.core.keyState != KeyState.ACTIVE) return null
            val fastAuthKey = record.core.fastAuthKey ?: return null
            val keyID = record.core.keyID ?: return null

            val isEngineCmd = (targetIns == Fast.INS_START_ENGINE || targetIns == Fast.INS_STOP_ENGINE)
            val payloadSize = 4 + (if (isEngineCmd) CryptoConstants.IMMOBILIZER_TOKEN_SIZE else 0)
            
            val plainPayload = ByteBuffer.allocate(payloadSize).apply {
                putInt(counter)
                if (isEngineCmd) put(record.immobilizerToken ?: ByteArray(64))
            }.array()

            val encrypted = CryptoUtils.encryptAesGcm(plainPayload, fastAuthKey)
            return ByteBuffer.allocate(keyID.size + encrypted.size).apply {
                put(keyID)
                put(encrypted)
            }.array()
        } catch (e: Exception) {
            return null
        }
    }

    private fun verifyCommitMarker(record: DigitalKeyRecord, encryptedResponse: ByteArray): Boolean {
        val fastAuthKey = record.core.fastAuthKey ?: return false
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(encryptedResponse, fastAuthKey)
            decrypted.isNotEmpty() && decrypted[0] == 0x00.toByte()
        } catch (e: Exception) {
            false
        }
    }
}

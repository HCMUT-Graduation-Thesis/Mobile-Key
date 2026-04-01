package com.example.a100_basiccrypto.digitalkey.transactions

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import android.os.Build
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
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * Owner Pairing Transaction - CCC 3.0 Standard OOB Pairing.
 * Handles Phase 3 with extended OOB parameters and Fast Auth Key derivation.
 */
class OwnerPairingTransaction(
    private val context: Context,
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

    private var localOobData: Any? = null
    private val executor = Executors.newSingleThreadExecutor()
    
    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        manager?.adapter
    }

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
        localOobData = null
    }

    override fun isTransactionComplete(): Boolean = isComplete

    private fun handleStartPairing(): LogicalResponse {
        onLog("Phase 1: Pairing Request")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && bluetoothAdapter != null) {
            try {
                val callbackClass = Class.forName("android.bluetooth.BluetoothAdapter\$OobDataCallback")
                val proxy = java.lang.reflect.Proxy.newProxyInstance(callbackClass.classLoader, arrayOf(callbackClass)) { _, method, args ->
                    if (method.name == "onOobData") { localOobData = args[1]; onLog("Phase 1: Local OOB ready") }
                    null
                }
                val generateMethod = bluetoothAdapter!!.javaClass.getMethod("generateLocalOobData", Int::class.java, java.util.concurrent.Executor::class.java, callbackClass)
                generateMethod.invoke(bluetoothAdapter, 2, executor, proxy)
            } catch (e: Exception) { Log.e(TAG, "OOB Init Error: ${e.message}") }
        }
        return LogicalResponse(Status.SUCCESS)
    }

    private fun handleExchangePubKey(payload: ByteArray): LogicalResponse {
        return try {
            val pubKeyReader = HandshakeProtector.parseUncompressedPublicKey(payload.sliceArray(0 until 65))
            ephemeralKeyPair = HandshakeProtector.generateEphemeralKeyPair()
            currentSessionKey = HandshakeProtector.deriveSessionKey(ephemeralKeyPair!!.private, pubKeyReader, passwordProvider().toByteArray(), CryptoConstants.OWNER_SESSION_INFO)
            LogicalResponse(Status.SUCCESS, HandshakeProtector.getRawUncompressedPublicKey(ephemeralKeyPair!!.public))
        } catch (e: Exception) { LogicalResponse(Status.ERR_GENERAL) }
    }

    private fun handleVerifyNonce(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            val responseData = decrypted.sliceArray(0 until 16) + identityCrypto.getPublicKey()
            LogicalResponse(Status.SUCCESS, CryptoUtils.encryptAesGcm(responseData, sessionKey))
        } catch (e: Exception) { LogicalResponse(Status.ERR_GENERAL) }
    }

    private fun handleExchangeVehicleData(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decryptedData = CryptoUtils.decryptAesGcm(payload, sessionKey)
            onLog("Phase 3: Data Received from Vehicle")

            val buffer = ByteBuffer.wrap(decryptedData)
            val record = DigitalKeyRecord()

            // 1. Dilithium PK (1952)
            val vehiclePK = ByteArray(CryptoConstants.ML_DSA_65_PK_SIZE)
            buffer.get(vehiclePK)
            record.core.vehiclePublicKey = vehiclePK

            // 2. Metadata & Identifiers
            val kid = ByteArray(8); buffer.get(kid)
            record.core.keyID = kid

            val mid = ByteArray(16); buffer.get(mid)
            record.core.moduleID = mid

            record.core.slotID = buffer.get()
            record.core.transactionCounter = buffer.int
            record.core.permissions = buffer.int
            record.core.validityStart = buffer.long
            record.core.validityEnd = buffer.long

            val token = ByteArray(64); buffer.get(token)
            record.core.immobilizerToken = token

            // 3. BLE Identity (6 + 16)
            val bleAddr = ByteArray(6); buffer.get(bleAddr)
            record.core.bleAddress = bleAddr

            val irk = ByteArray(16); buffer.get(irk)
            record.core.irk = irk

            // 4. BLE OOB (65 + 16 + 16)
            val blePk = ByteArray(65); buffer.get(blePk)
            record.core.bleVehiclePublicKey = blePk

            val conf = ByteArray(16); buffer.get(conf)
            record.core.oobConfirmation = conf

            val rand = ByteArray(16); buffer.get(rand)
            record.core.oobRandomizer = rand

            // 5. Metadata JSON (Remaining)
            val metaLen = buffer.remaining()
            if (metaLen > 0) {
                val metaBytes = ByteArray(metaLen); buffer.get(metaBytes)
                record.core.carMetadata = gson.fromJson(String(metaBytes), CarMetadata::class.java)
                record.friendlyName = record.core.carMetadata?.modelName ?: "My Vehicle"
            }

            // 6. Fast Auth Key Derivation
            onLog("Phase 3: Deriving Fast Auth Key...")
            val salt = passwordProvider().toByteArray()
            record.core.fastAuthKey = CryptoUtils.deriveSessionKey(
                sessionKey, salt, CryptoConstants.FAST_AUTH_TAG.toByteArray(), 32
            )

            record.devicePrivateKey = identityCrypto.getPrivateKey()
            record.core.devicePublicKey = identityCrypto.getPublicKey()
            record.core.keyState = KeyState.PROVISIONING
            pendingRecord = record
            storageManager.saveDigitalKey(record)

            // 7. Prepare Response: App -> Vehicle
            onLog("Phase 3: Preparing BLE OOB Response...")
            val appAddr = bleIdentityManager.getAppBleAddress()
            val appIrk = bleIdentityManager.getAppIrk()
            val oob = localOobData
            
            val appConf = if (oob != null) oob.javaClass.getMethod("getLeConfirmationHash").invoke(oob) as ByteArray else ByteArray(16)
            val appRand = if (oob != null) oob.javaClass.getMethod("getLeRandomizerHash").invoke(oob) as ByteArray else ByteArray(16)
            val appPk = if (oob != null) oob.javaClass.getMethod("getLeTemporaryKey").invoke(oob) as ByteArray else ByteArray(65)

            val appKeyId = ByteArray(8).apply { SecureRandom().nextBytes(this) }

            // Response: PK(1952) + KeyID(8) + Addr(6) + IRK(16) + PK(65) + Conf(16) + Rand(16)
            val response = ByteBuffer.allocate(1952 + 8 + 6 + 16 + 65 + 16 + 16).apply {
                put(record.core.devicePublicKey!!)
                put(appKeyId)
                put(appAddr)
                put(appIrk)
                put(appPk)
                put(appConf)
                put(appRand)
            }.array()

            LogicalResponse(Status.SUCCESS, CryptoUtils.encryptAesGcm(response, sessionKey))
        } catch (e: Exception) {
            Log.e(TAG, "Phase 3 Error: ${e.message}")
            LogicalResponse(Status.ERR_GENERAL)
        }
    }

    private fun handleCommitPairing(payload: ByteArray): LogicalResponse {
        val sessionKey = currentSessionKey ?: return LogicalResponse(Status.ERR_GENERAL)
        return try {
            val decrypted = CryptoUtils.decryptAesGcm(payload, sessionKey)
            if (decrypted.size == 1 && decrypted[0] == 0x01.toByte()) {
                pendingRecord?.let { 
                    it.core.keyState = KeyState.ACTIVE
                    storageManager.saveDigitalKey(it)
                    onLog("Phase 4: Pairing Active!")
                }
                isComplete = true
                LogicalResponse(Status.SUCCESS)
            } else LogicalResponse(Status.ERR_GENERAL)
        } catch (e: Exception) { LogicalResponse(Status.ERR_GENERAL) }
    }
}

package com.example.a100_basiccrypto.digitalkey.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.normalize
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.physical.BleConstants
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * BleCentralManager - Implements Secure L2CAP PSM exchange using AES-GCM and ModuleID.
 * Updated: Account-aware filtering using AuthManager.
 */
@SuppressLint("MissingPermission")
class BleCentralManager(
    private val context: Context,
    private val authManager: AuthManager,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "BleCentralManager"
        private const val SCAN_PERIOD: Long = 12000 
        private const val RECONNECT_DELAY: Long = 3000
        private const val GCM_IV_LENGTH = 12
    }

    var onDataReceived: ((ByteArray) -> Unit)? = null
    var onVehicleInfoUpdated: ((moduleID: String, mac: String, psm: Int) -> Unit)? = null
    var onConnectionStateChanged: ((Boolean) -> Unit)? = null

    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        manager?.adapter
    }

    private val storageManager by lazy { SecureKeyStorageManager(context) }
    private val handler = Handler(Looper.getMainLooper())
    private var isScanning = false
    private var isConnected = false
    private var bluetoothSocket: BluetoothSocket? = null
    private var bluetoothGatt: BluetoothGatt? = null
    
    private var targetRecord: DigitalKeyRecord? = null
    
    /**
     * The KeyID of the currently connected and verified vehicle.
     */
    var connectedKeyID: ByteArray? = null
        private set

    fun isConnected(): Boolean = isConnected

    fun scanAndConnect(record: DigitalKeyRecord) {
        if (!authManager.isLoggedIn()) {
            onLog("BLE Error: No user logged in.")
            return
        }
        targetRecord = record
        if (isConnected || isScanning) return
        startScanSequence()
    }

    private fun startScanSequence() {
        if (isConnected || isScanning || bluetoothAdapter?.isEnabled != true) return
        val scanner = bluetoothAdapter?.bluetoothLeScanner ?: return

        onLog("BLE: Searching for vehicle...")
        val filters = listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(BleConstants.SERVICE_UUID)).build())
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()

        isScanning = true
        try {
            scanner.startScan(filters, settings, scanCallback)
        } catch (e: Exception) {
            isScanning = false
            scheduleReconnect()
            return
        }

        handler.postDelayed({
            if (isScanning) {
                onLog("BLE: Scan timeout. Restarting...")
                stopScan()
                scheduleReconnect()
            }
        }, SCAN_PERIOD)
    }

    private fun stopScan() {
        if (!isScanning) return
        try { bluetoothAdapter?.bluetoothLeScanner?.stopScan(scanCallback) } catch (e: Exception) {}
        isScanning = false
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            if (!isScanning) return
            stopScan()
            onLog("BLE: Vehicle found (${result.device.address}). Verifying Identity...")
            connectGatt(result.device)
        }
    }

    private fun connectGatt(device: BluetoothDevice) {
        bluetoothGatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                onLog("BLE: Link established. Reading Module ID...")
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                onLog("BLE: Link lost.")
                handleDisconnection()
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val service = gatt.getService(BleConstants.SERVICE_UUID)
            val moduleChar = service?.getCharacteristic(BleConstants.MODULE_ID_CHARACTERISTIC_UUID)
            if (moduleChar != null) {
                gatt.readCharacteristic(moduleChar)
            } else {
                onLog("BLE Error: Identity service missing.")
                handleDisconnection()
            }
        }

        @Deprecated("Deprecated in Java")
        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                onLog("BLE Error: Read failed with status $status")
                return
            }

            when (characteristic.uuid) {
                BleConstants.MODULE_ID_CHARACTERISTIC_UUID -> {
                    val receivedModuleId = characteristic.value
                    if (verifyVehicleIdentity(receivedModuleId)) {
                        onLog("BLE: Identity Verified! Syncing Secure PSM...")
                        val psmChar = gatt.getService(BleConstants.SERVICE_UUID)
                            ?.getCharacteristic(BleConstants.PSM_CHARACTERISTIC_UUID)
                        if (psmChar != null) gatt.readCharacteristic(psmChar)
                    } else {
                        onLog("BLE: Unauthorized vehicle detected or account mismatch.")
                        handleDisconnection()
                    }
                }
                BleConstants.PSM_CHARACTERISTIC_UUID -> {
                    val receivedPayload = characteristic.value
                    if (receivedPayload == null || receivedPayload.isEmpty()) {
                        onLog("BLE Error: Empty PSM data.")
                        handleDisconnection()
                        return
                    }

                    val mid = targetRecord?.moduleID
                    if (mid == null || mid.isEmpty()) {
                        onLog("BLE Error: ModuleID missing for decryption.")
                        handleDisconnection()
                        return
                    }

                    try {
                        // Use normalized ModuleID as AES-256 key
                        val aesKey = mid.normalize(32)
                        val zeroIv = ByteArray(GCM_IV_LENGTH) { 0 }
                        val fullCipherData = zeroIv + receivedPayload

                        val decryptedBytes = CryptoUtils.decryptAesGcm(fullCipherData, aesKey)
                        val psm = ByteBuffer.wrap(decryptedBytes).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                        
                        onLog("BLE: PSM Decrypted. Opening L2CAP...")
                        
                        targetRecord?.moduleID?.let { mId ->
                            onVehicleInfoUpdated?.invoke(mId.joinToString("") { "%02x".format(it) }, gatt.device.address, psm)
                        }
                        
                        openInsecureL2capChannel(gatt.device, psm)
                    } catch (e: Exception) {
                        onLog("BLE Security Error: PSM Decryption failed.")
                        handleDisconnection()
                    }
                }
            }
        }
    }

    private fun verifyVehicleIdentity(receivedId: ByteArray?): Boolean {
        if (receivedId == null) return false

        val currentEmail = authManager.getUserEmail() ?: return false
        
        // 1. Check in storage for existing keys belonging to CURRENT account
        val myKeys = storageManager.getKeysByAccount(currentEmail)
        val matchingRecord = myKeys.find { it.moduleID?.contentEquals(receivedId) == true }
        
        if (matchingRecord != null) {
            targetRecord = matchingRecord
            connectedKeyID = matchingRecord.core.keyID
            return true
        }
        
        // 2. Fallback for Owner Pairing: If we are scanning a new record with no moduleID yet
        val currentTarget = targetRecord
        if (currentTarget != null && (currentTarget.moduleID == null || currentTarget.moduleID!!.isEmpty())) {
            currentTarget.moduleID = receivedId
            onLog("BLE: Vehicle Identity acquired. Proceeding...")
            return true
        }

        return false
    }

    private fun openInsecureL2capChannel(device: BluetoothDevice, psm: Int) {
        Thread {
            try {
                bluetoothSocket = device.createInsecureL2capChannel(psm)
                bluetoothSocket?.connect()
                isConnected = true
                onLog("BLE: L2CAP Data pipe connected.")
                handler.post { onConnectionStateChanged?.invoke(true) }
                
                val inputStream = bluetoothSocket?.inputStream ?: return@Thread
                val buffer = ByteArray(8192)
                while (isConnected) {
                    val bytes = inputStream.read(buffer)
                    if (bytes > 0) onDataReceived?.invoke(buffer.copyOfRange(0, bytes))
                }
            } catch (e: IOException) {
                onLog("BLE: L2CAP Connection failed.")
                handleDisconnection()
            }
        }.start()
    }

    private fun handleDisconnection() {
        val wasConnected = isConnected
        isConnected = false
        connectedKeyID = null // Reset on disconnection
        closeEverything()
        if (wasConnected) {
            handler.post { onConnectionStateChanged?.invoke(false) }
        }
        scheduleReconnect()
    }

    private fun scheduleReconnect() {
        handler.removeCallbacksAndMessages(null)
        if (targetRecord != null) {
            handler.postDelayed({ startScanSequence() }, RECONNECT_DELAY)
        }
    }

    fun sendData(data: ByteArray) {
        if (!isConnected) return
        Thread {
            try { bluetoothSocket?.outputStream?.write(data) } catch (e: Exception) {}
        }.start()
    }

    fun closeEverything() {
        val wasConnected = isConnected
        isConnected = false
        connectedKeyID = null
        stopScan()
        handler.removeCallbacksAndMessages(null)
        try { bluetoothSocket?.close() } catch (e: Exception) {}
        try { bluetoothGatt?.close() } catch (e: Exception) {}
        bluetoothSocket = null
        bluetoothGatt = null
        
        if (wasConnected) {
            handler.post { onConnectionStateChanged?.invoke(false) }
        }
    }
}

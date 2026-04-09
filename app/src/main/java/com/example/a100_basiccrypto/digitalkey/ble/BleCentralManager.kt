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
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.physical.BleConstants
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * BleCentralManager - Implements Secure L2CAP PSM exchange using AES-GCM and ImmoToken.
 * Updated to match Technical Spec: Little Endian PSM and 32-byte sliced ImmoToken.
 */
@SuppressLint("MissingPermission")
class BleCentralManager(
    private val context: Context,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "BleCentralManager"
        private const val SCAN_PERIOD: Long = 12000 
        private const val RECONNECT_DELAY: Long = 3000
        private const val GCM_IV_LENGTH = 12
    }

    var onDataReceived: ((ByteArray) -> Unit)? = null
    
    // Callback to send dynamic vehicle info (MAC, PSM) back to UI
    var onVehicleInfoUpdated: ((moduleID: String, mac: String, psm: Int) -> Unit)? = null

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
    
    // The record we are currently trying to verify against
    private var targetRecord: DigitalKeyRecord? = null

    private fun isBluetoothEnabled(): Boolean = bluetoothAdapter?.isEnabled == true

    fun isConnected(): Boolean = isConnected

    fun scanAndConnect(record: DigitalKeyRecord) {
        targetRecord = record
        if (!isBluetoothEnabled() || isConnected || isScanning) return
        startScanSequence()
    }

    private fun startScanSequence() {
        if (isConnected || isScanning || !isBluetoothEnabled()) return
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
            
            // Step 1: Verify Module ID
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
                        // Step 2: If identity is correct, read encrypted PSM
                        val psmChar = gatt.getService(BleConstants.SERVICE_UUID)
                            ?.getCharacteristic(BleConstants.PSM_CHARACTERISTIC_UUID)
                        if (psmChar != null) gatt.readCharacteristic(psmChar)
                    } else {
                        onLog("BLE: Unauthorized vehicle detected. Disconnecting.")
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

                    // LOG RAW PSM INFO (18 bytes: 2 bytes Ciphertext + 16 bytes Tag)
                    onLog("BLE: Received Payload (Length: ${receivedPayload.size} bytes)")
                    Log.d(TAG, "Raw Payload: ${receivedPayload.toHex()}")

                    val fullToken = targetRecord?.immobilizerToken
                    if (fullToken == null || fullToken.size < 32) {
                        onLog("BLE Error: Invalid or missing ImmoToken (Requires 32 bytes).")
                        handleDisconnection()
                        return
                    }

                    try {
                        // SPEC COMPLIANCE: Use only first 32 bytes of ImmoToken as AES-256 key
                        val aesKey = fullToken.sliceArray(0 until 32)
                        
                        // MTU OPTIMIZATION: Vehicle uses a static zero IV (12 bytes)
                        val zeroIv = ByteArray(GCM_IV_LENGTH) { 0 }
                        val fullCipherData = zeroIv + receivedPayload

                        // Step 3: Decrypt using AES/GCM/NoPadding
                        val decryptedBytes = CryptoUtils.decryptAesGcm(fullCipherData, aesKey)
                        
                        // Step 4: Convert 2-byte plaintext to Int using LITTLE ENDIAN (as per spec)
                        // Formula: (data[0] & 0xFF) | ((data[1] & 0xFF) << 8)
                        val psm = ByteBuffer.wrap(decryptedBytes).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                        
                        onLog("BLE: PSM Decrypted (Value: 0x${Integer.toHexString(psm).uppercase()}, Int: $psm). Opening L2CAP...")
                        Log.d(TAG, "Decrypted PSM: $psm (0x${Integer.toHexString(psm).uppercase()})")
                        
                        // BROADCAST INFO TO UI
                        targetRecord?.moduleID?.let { mid ->
                            onVehicleInfoUpdated?.invoke(mid.joinToString("") { "%02x".format(it) }, gatt.device.address, psm)
                        }
                        
                        openInsecureL2capChannel(gatt.device, psm)
                    } catch (e: Exception) {
                        onLog("BLE Security Error: PSM Decryption failed (AEAD check failed).")
                        Log.e(TAG, "Decryption error", e)
                        handleDisconnection()
                    }
                }
            }
        }
    }

    private fun verifyVehicleIdentity(receivedId: ByteArray?): Boolean {
        if (receivedId == null) return false
        val savedKeys = storageManager.getAllKeys().filter { it.core.keyState == KeyState.ACTIVE }
        
        // Check if the received Module ID exists in our local key database
        for (record in savedKeys) {
            if (record.moduleID.contentEquals(receivedId)) {
                targetRecord = record // Update targetRecord to the matched one
                return true
            }
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
        isConnected = false
        closeEverything()
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
        isConnected = false
        stopScan()
        handler.removeCallbacksAndMessages(null)
        try { bluetoothSocket?.close() } catch (e: Exception) {}
        try { bluetoothGatt?.close() } catch (e: Exception) {}
        bluetoothSocket = null
        bluetoothGatt = null
    }

    private fun ByteArray?.toHex(): String = this?.joinToString("") { "%02x".format(it) } ?: ""
}

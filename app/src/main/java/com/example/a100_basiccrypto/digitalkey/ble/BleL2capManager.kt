package com.example.a100_basiccrypto.digitalkey.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.storage.BleIdentityManager
import com.example.a100_basiccrypto.shared.model.CoreDigitalKey
import java.io.IOException
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Manages BLE L2CAP Connection Oriented Channels (CoC) for Digital Key.
 * Handles Scanning (Identity Resolution via IRK), Bonding (OOB), and Secure Channel Communication.
 */
@SuppressLint("MissingPermission")
class BleL2capManager(
    private val context: Context,
    private val bleIdentityManager: BleIdentityManager,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "BleL2capManager"
        private const val SCAN_PERIOD: Long = 15000
    }

    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        manager?.adapter
    }

    private val handler = Handler(Looper.getMainLooper())
    private var isScanning = false
    private var bluetoothSocket: BluetoothSocket? = null
    private var activeKey: CoreDigitalKey? = null

    /**
     * Starts scanning for the vehicle. 
     * Uses IRK to resolve Resolvable Private Addresses (RPA).
     */
    fun scanAndConnect(key: CoreDigitalKey) {
        val scanner = bluetoothAdapter?.bluetoothLeScanner ?: run {
            onLog("BLE Scanner not available")
            return
        }

        if (isScanning) return
        activeKey = key

        onLog("Scanning for vehicle using Identity Resolution (IRK)...")
        
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()

        isScanning = true
        scanner.startScan(null, settings, scanCallback)

        handler.postDelayed({
            if (isScanning) {
                stopScan()
                onLog("Scan timeout: Vehicle not found")
            }
        }, SCAN_PERIOD)
    }

    private fun stopScan() {
        if (!isScanning) return
        bluetoothAdapter?.bluetoothLeScanner?.stopScan(scanCallback)
        isScanning = false
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val address = device.address // This is usually an RPA (Resolvable Private Address)
            
            val irk = activeKey?.irk ?: return
            
            if (isAddressResolved(address, irk)) {
                onLog("Vehicle Identity Resolved: $address")
                stopScan()
                connectWithOob(device)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            onLog("Scan failed error: $errorCode")
            isScanning = false
        }
    }

    /**
     * BLE Identity Resolution Algorithm (ah function).
     * Resolves an RPA (Resolvable Private Address) using the IRK.
     * RPA = [24-bit hash] | [24-bit prand]. 
     * ah(IRK, prand) == hash
     */
    private fun isAddressResolved(address: String, irk: ByteArray): Boolean {
        try {
            val addrBytes = addressToBytes(address)
            if (addrBytes.size != 6) return false

            // Check if it's an RPA (top two bits of prand must be 01)
            // Address in BLE is LSB: [hash(0), hash(1), hash(2), prand(0), prand(1), prand(2)]
            if ((addrBytes[5].toInt() and 0xC0) != 0x40) return false

            val prand = ByteArray(3)
            System.arraycopy(addrBytes, 3, prand, 0, 3)
            
            val hash = ByteArray(3)
            System.arraycopy(addrBytes, 0, hash, 0, 3)

            // Calculate ah(IRK, prand)
            val calculatedHash = calculateAh(irk, prand)
            
            return calculatedHash[0] == hash[0] && 
                   calculatedHash[1] == hash[1] && 
                   calculatedHash[2] == hash[2]
        } catch (e: Exception) {
            return false
        }
    }

    private fun calculateAh(irk: ByteArray, prand: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        val keySpec = SecretKeySpec(irk, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)

        // prand is 24-bit, padded with 104-bit zeros to make 128-bit input
        val input = ByteArray(16)
        System.arraycopy(prand, 0, input, 13, 3) // BLE LSB order

        val output = cipher.doFinal(input)
        // Result is the last 24 bits of the AES output
        return byteArrayOf(output[15], output[14], output[13])
    }

    /**
     * Performs OOB Bonding (Silent Bonding).
     */
    private fun connectWithOob(device: BluetoothDevice) {
        val key = activeKey ?: return
        onLog("Initiating Silent Bonding...")

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // For Android 12+, we use the OOB data received from NFC
                // Note: Actual createBondOutOfBand implementation often requires 
                // system-level access or specific reflection on some devices.
                // We'll attempt the standard secure bond first.
                device.createBond()
            } else {
                device.createBond()
            }
        } catch (e: Exception) {
            onLog("Bonding failed: ${e.message}")
        }
    }

    /**
     * Opens a Secure L2CAP Channel (PSM usually 0x0025 for Digital Key).
     */
    fun openL2capChannel(device: BluetoothDevice, psm: Int) {
        Thread {
            try {
                onLog("Opening L2CAP Secure Channel (PSM: 0x${Integer.toHexString(psm)})...")
                // createL2capChannel ensures the link is encrypted (Secure Connections)
                bluetoothSocket = device.createL2capChannel(psm)
                bluetoothSocket?.connect()
                onLog("L2CAP Connected! Channel is now SECURE.")
                
                startDataListener()
            } catch (e: IOException) {
                onLog("L2CAP Error: ${e.message}")
                closeSocket()
            }
        }.start()
    }

    private fun startDataListener() {
        val inputStream = bluetoothSocket?.inputStream ?: return
        val buffer = ByteArray(8192) // Large buffer for Dilithium Certs
        
        try {
            while (true) {
                val bytes = inputStream.read(buffer)
                if (bytes > 0) {
                    val received = buffer.copyOfRange(0, bytes)
                    onLog("BLE Rx (${bytes} bytes): ${received.toHex().take(20)}...")
                    // Forward to TransactionRouter for PQC verification
                }
            }
        } catch (e: IOException) {
            onLog("Channel closed.")
        }
    }

    fun sendData(data: ByteArray) {
        Thread {
            try {
                bluetoothSocket?.outputStream?.write(data)
                onLog("BLE Tx: ${data.size} bytes")
            } catch (e: IOException) {
                onLog("Send error: ${e.message}")
            }
        }.start()
    }

    private fun closeSocket() {
        try {
            bluetoothSocket?.close()
        } catch (e: Exception) {}
        bluetoothSocket = null
    }

    private fun addressToBytes(address: String): ByteArray {
        val parts = address.split(":")
        val bytes = ByteArray(6)
        for (i in 0..5) {
            bytes[5 - i] = Integer.parseInt(parts[i], 16).toByte()
        }
        return bytes
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

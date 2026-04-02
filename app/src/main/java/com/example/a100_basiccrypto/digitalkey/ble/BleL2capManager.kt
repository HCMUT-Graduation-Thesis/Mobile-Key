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
import com.example.a100_basiccrypto.shared.model.CoreDigitalKey
import java.io.IOException
import java.util.*

/**
 * Manages BLE L2CAP Insecure Channels (Mode 1 - Level 1).
 * Optimized for high speed and no OS pairing popups.
 */
@SuppressLint("MissingPermission")
class BleL2capManager(
    private val context: Context,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "BleL2capManager"
        private const val SCAN_PERIOD: Long = 10000
        
        // Cấu hình theo tài liệu kỹ thuật
        val SERVICE_UUID: UUID = UUID.fromString("0000FF01-0000-1000-8000-00805F9B34FB")
        val PSM_CHARACTERISTIC_UUID: UUID = UUID.fromString("0000FF02-0000-1000-8000-00805F9B34FB")
    }

    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        manager?.adapter
    }

    private val handler = Handler(Looper.getMainLooper())
    private var isScanning = false
    private var bluetoothSocket: BluetoothSocket? = null
    private var activeKey: CoreDigitalKey? = null
    private var bluetoothGatt: BluetoothGatt? = null

    /**
     * Giai đoạn 2: Rà quét và Định danh (Scanning) sử dụng Service UUID
     */
    fun scanAndConnect(key: CoreDigitalKey) {
        val scanner = bluetoothAdapter?.bluetoothLeScanner ?: return
        if (isScanning) return
        activeKey = key

        onLog("Scanning for vehicle (Service UUID: ${SERVICE_UUID.toString().take(8)})...")
        
        val filters = listOf(
            ScanFilter.Builder()
                .setServiceUuid(ParcelUuid(SERVICE_UUID))
                .build()
        )
        
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        isScanning = true
        scanner.startScan(filters, settings, scanCallback)

        handler.postDelayed({ stopScan() }, SCAN_PERIOD)
    }

    private fun stopScan() {
        if (!isScanning) return
        bluetoothAdapter?.bluetoothLeScanner?.stopScan(scanCallback)
        isScanning = false
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            onLog("Vehicle detected: ${result.device.address}")
            stopScan()
            connectGatt(result.device)
        }
    }

    /**
     * Thiết lập cầu nối vật lý (ACL) - Mode 1 Level 1
     */
    private fun connectGatt(device: BluetoothDevice) {
        onLog("Connecting GATT (Physical Link)...")
        bluetoothGatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                onLog("GATT Connected. Discovering services...")
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                onLog("GATT Disconnected.")
                closeEverything()
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                // Bước Then Chốt: Cập nhật thông số định tuyến (PSM)
                val service = gatt.getService(SERVICE_UUID)
                val characteristic = service?.getCharacteristic(PSM_CHARACTERISTIC_UUID)
                if (characteristic != null) {
                    onLog("Reading PSM from Vehicle...")
                    gatt.readCharacteristic(characteristic)
                } else {
                    onLog("Error: PSM Characteristic not found!")
                }
            }
        }

        @Deprecated("Deprecated in Java")
        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == PSM_CHARACTERISTIC_UUID) {
                val psm = characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT16, 0)
                onLog("Received Dynamic PSM: $psm")
                openInsecureL2capChannel(gatt.device, psm)
            }
        }
    }

    /**
     * Mở đường ống truyền tải tốc độ cao (L2CAP Insecure)
     */
    private fun openInsecureL2capChannel(device: BluetoothDevice, psm: Int) {
        Thread {
            try {
                onLog("Opening Insecure L2CAP Socket (PSM: $psm)...")
                // Quan trọng: Sử dụng createInsecureL2capChannel để bypass Pairing
                bluetoothSocket = device.createInsecureL2capChannel(psm)
                bluetoothSocket?.connect()
                
                onLog("L2CAP Connected successfully (No Security)!")
                startDataListener()
            } catch (e: IOException) {
                onLog("L2CAP Connection failed: ${e.message}")
                closeEverything()
            }
        }.start()
    }

    private fun startDataListener() {
        val inputStream = bluetoothSocket?.inputStream ?: return
        val buffer = ByteArray(4096)
        try {
            while (true) {
                val bytes = inputStream.read(buffer)
                if (bytes > 0) {
                    val data = buffer.copyOfRange(0, bytes)
                    onLog("L2CAP Rx: ${bytes} bytes")
                }
            }
        } catch (e: IOException) {
            onLog("L2CAP Stream closed.")
        }
    }

    fun sendData(data: ByteArray) {
        Thread {
            try {
                bluetoothSocket?.outputStream?.write(data)
                onLog("L2CAP Tx: ${data.size} bytes")
            } catch (e: IOException) {
                onLog("Send error: ${e.message}")
            }
        }.start()
    }

    private fun closeEverything() {
        try {
            bluetoothSocket?.close()
            bluetoothGatt?.disconnect()
            bluetoothGatt?.close()
        } catch (e: Exception) {}
        bluetoothSocket = null
        bluetoothGatt = null
    }
}

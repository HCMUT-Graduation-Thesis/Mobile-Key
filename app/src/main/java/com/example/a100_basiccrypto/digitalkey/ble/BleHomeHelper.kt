package com.example.a100_basiccrypto.digitalkey.ble

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

/**
 * BleHomeHelper - Encapsulates Bluetooth enablement logic and state monitoring.
 * Fixed: Handles Android 12+ runtime permissions to prevent SecurityException.
 */
class BleHomeHelper(
    private val activity: AppCompatActivity,
    private val onStateChanged: (Boolean) -> Unit
) {
    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val manager = activity.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        manager?.adapter
    }

    private lateinit var enableBluetoothLauncher: ActivityResultLauncher<Intent>
    private lateinit var requestPermissionLauncher: ActivityResultLauncher<Array<String>>

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                onStateChanged(isBluetoothEnabled())
            }
        }
    }

    /**
     * Must be called in Activity.onCreate()
     */
    fun initLauncher(onSuccess: () -> Unit) {
        enableBluetoothLauncher = activity.registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == AppCompatActivity.RESULT_OK) {
                onSuccess()
                onStateChanged(true)
            } else {
                Toast.makeText(activity, "Bluetooth is required for this app", Toast.LENGTH_LONG).show()
                activity.finish()
            }
        }

        requestPermissionLauncher = activity.registerForActivityResult(
            ActivityResultContracts.RequestMultiplePermissions()
        ) { permissions ->
            val allGranted = permissions.entries.all { it.value }
            if (allGranted) {
                // Permissions granted, now safe to check Bluetooth state
                checkBluetoothAndRequest()
            } else {
                Toast.makeText(activity, "Bluetooth permissions are required", Toast.LENGTH_LONG).show()
                activity.finish()
            }
        }
    }

    fun checkBluetoothAndRequest() {
        if (bluetoothAdapter == null) {
            Toast.makeText(activity, "Bluetooth not supported on this device", Toast.LENGTH_LONG).show()
            activity.finish()
            return
        }

        // 1. Check Runtime Permissions for Android 12+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val hasConnectPermission = ContextCompat.checkSelfPermission(activity, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
            val hasScanPermission = ContextCompat.checkSelfPermission(activity, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
            
            if (!hasConnectPermission || !hasScanPermission) {
                requestPermissionLauncher.launch(arrayOf(
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_SCAN
                ))
                return
            }
        }

        // 2. Request to Enable Bluetooth if OFF
        if (!bluetoothAdapter!!.isEnabled) {
            try {
                val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                enableBluetoothLauncher.launch(enableBtIntent)
            } catch (e: SecurityException) {
                Toast.makeText(activity, "Security Error: Missing Bluetooth Permissions", Toast.LENGTH_LONG).show()
            }
        } else {
            onStateChanged(true)
        }
    }

    fun isBluetoothEnabled(): Boolean = bluetoothAdapter?.isEnabled == true

    fun registerReceiver() {
        ContextCompat.registerReceiver(
            activity,
            bluetoothStateReceiver,
            IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_EXPORTED
        )
    }

    fun unregisterReceiver() {
        try {
            activity.unregisterReceiver(bluetoothStateReceiver)
        } catch (e: Exception) {}
    }
}

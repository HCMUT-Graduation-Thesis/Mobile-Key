package com.example.a100_basiccrypto.digitalkey.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

/**
 * BleHomeHelper - Encapsulates Bluetooth enablement logic and state monitoring.
 * Keeps HomeActivity clean.
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

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                onStateChanged(isBluetoothEnabled())
            }
        }
    }

    /**
     * Must be called in Activity.onCreate() or before it starts.
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
    }

    fun checkBluetoothAndRequest() {
        if (bluetoothAdapter == null) {
            Toast.makeText(activity, "Bluetooth not supported on this device", Toast.LENGTH_LONG).show()
            activity.finish()
            return
        }

        if (!bluetoothAdapter!!.isEnabled) {
            val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
            enableBluetoothLauncher.launch(enableBtIntent)
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
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    fun unregisterReceiver() {
        try {
            activity.unregisterReceiver(bluetoothStateReceiver)
        } catch (e: Exception) {
            // Already unregistered
        }
    }
}

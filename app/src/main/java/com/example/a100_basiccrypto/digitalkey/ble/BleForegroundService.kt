package com.example.a100_basiccrypto.digitalkey.ble

import android.app.*
import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.a100_basiccrypto.HomeActivity
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransactionClient
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import kotlinx.coroutines.*

/**
 * Foreground Service to maintain BLE connection and perform background telemetry sync.
 */
class BleForegroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "ble_connection_channel"
        private const val NOTIFICATION_ID = 101
        private const val NORMAL_INTERVAL = 15000L // 20 seconds
        private const val FAST_INTERVAL = 3000L   // 3 seconds
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var telemetryJob: Job? = null
    private var currentInterval = NORMAL_INTERVAL
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val fastTxClient by lazy { 
        FastTransactionClient(storageManager) { Log.d("BleService", it) } 
    }

    private val bluetoothReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                when (state) {
                    BluetoothAdapter.STATE_ON -> {
                        Log.d("BleService", "Bluetooth turned ON, restarting scan...")
                        triggerAutoScan()
                    }
                    BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> {
                        Log.d("BleService", "Bluetooth turned OFF, cleaning up connection.")
                        BleProvider.getManager().closeEverything()
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        BleProvider.init(this)
        
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        registerReceiver(bluetoothReceiver, filter)
        
        BleProvider.setSyncTriggerListener {
            serviceScope.launch {
                performSingleSync()
            }
        }

        BleProvider.setPollingSpeedListener { isFast ->
            val newInterval = if (isFast) FAST_INTERVAL else NORMAL_INTERVAL
            if (currentInterval != newInterval) {
                currentInterval = newInterval
                Log.d("BleService", "Polling interval changed to: ${currentInterval}ms")
                startTelemetryPolling() // Restart with new interval
            }
        }
        
        startTelemetryPolling()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Digital Key Active")
            .setContentText("Scanning for your vehicle in the background...")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, HomeActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        triggerAutoScan()

        return START_STICKY
    }

    private fun triggerAutoScan() {
        val manager = BleProvider.getManager()
        if (!manager.isConnected()) {
            val activeKeys = storageManager.getAllKeys().filter { it.core.keyState == KeyState.ACTIVE }
            if (activeKeys.isNotEmpty()) {
                manager.scanAndConnect(activeKeys[0])
            }
        }
    }

    private fun startTelemetryPolling() {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            while (isActive) {
                performSingleSync()
                delay(currentInterval)
            }
        }
    }

    private suspend fun performSingleSync() {
        val manager = BleProvider.getManager()
        val activeKeyID = manager.connectedKeyID
        
        if (manager.isConnected() && activeKeyID != null) {
            Log.d("BleService", "Starting telemetry sync for: ${activeKeyID.toHex()}")
            val status = fastTxClient.syncTelemetry(BleProvider.getTransport(), activeKeyID)
            
            if (status != null) {
                withContext(Dispatchers.Main) {
                    BleProvider.notifyTelemetryUpdated(status)
                }
            }
        }
    }

    override fun onDestroy() {
        BleProvider.setSyncTriggerListener(null)
        BleProvider.setPollingSpeedListener(null)
        unregisterReceiver(bluetoothReceiver)
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Digital Key Service", NotificationManager.IMPORTANCE_LOW)
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }
}

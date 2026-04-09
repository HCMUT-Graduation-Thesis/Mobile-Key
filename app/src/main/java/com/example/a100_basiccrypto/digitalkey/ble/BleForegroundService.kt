package com.example.a100_basiccrypto.digitalkey.ble

import android.app.*
import android.content.Intent
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
        private const val TELEMETRY_POLL_INTERVAL = 15000L //  15 seconds
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var telemetryJob: Job? = null
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val fastTxClient by lazy { 
        FastTransactionClient(storageManager) { Log.d("BleService", it) } 
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        BleProvider.init(this)
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

        // Auto-scan for active keys if not already connected
        val manager = BleProvider.getManager()
        if (!manager.isConnected()) {
            val activeKeys = storageManager.getAllKeys().filter { it.core.keyState == KeyState.ACTIVE }
            if (activeKeys.isNotEmpty()) {
                manager.scanAndConnect(activeKeys[0])
            }
        }

        return START_STICKY
    }

    private fun startTelemetryPolling() {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            while (isActive) {
                val manager = BleProvider.getManager()
                val activeKeyID = manager.connectedKeyID
                
                if (manager.isConnected() && activeKeyID != null) {
                    Log.d("BleService", "Starting background telemetry sync for: ${activeKeyID.toHex()}")
                    val status = fastTxClient.syncTelemetry(BleProvider.getTransport(), activeKeyID)
                    
                    // Broadcast the update to any active UI listeners
                    if (status != null) {
                        withContext(Dispatchers.Main) {
                            BleProvider.notifyTelemetryUpdated(status)
                        }
                    }
                }
                delay(TELEMETRY_POLL_INTERVAL)
            }
        }
    }

    override fun onDestroy() {
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

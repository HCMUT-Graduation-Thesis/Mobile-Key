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
        private const val TELEMETRY_POLL_INTERVAL = 15000L // 15 seconds
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
        if (!BleProvider.getManager().isConnected()) {
            val activeKeys = storageManager.getAllKeys().filter { it.core.keyState == KeyState.ACTIVE }
            if (activeKeys.isNotEmpty()) {
                BleProvider.getManager().scanAndConnect(activeKeys[0])
            }
        }

        return START_STICKY
    }

    private fun startTelemetryPolling() {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            while (isActive) {
                if (BleProvider.getManager().isConnected()) {
                    trySyncCurrentVehicle()
                }
                delay(TELEMETRY_POLL_INTERVAL)
            }
        }
    }

    private suspend fun trySyncCurrentVehicle() {
        // 1. Get the ModuleID of the currently connected vehicle from the GATT cache
        // BleProvider updates this when identity is verified in BleCentralManager
        val allKeys = storageManager.getAllKeys()
        
        // Find which key record matches the connected device
        // We can use the logic from verifyVehicleIdentity but in reverse or check BleProvider's state
        val connectedRecord = allKeys.find { record ->
            val midHex = record.moduleID?.toHex() ?: ""
            // We need a way to know which MID is currently connected. 
            // BleCentralManager stores the connected GATT device, but we verified the MID during handshake.
            // For now, we assume the record that matches the verification is the one.
            BleProvider.getManager().isConnected() && midHex.isNotEmpty() 
            // In a real scenario, we'd store the verified KeyID in BleProvider after handshake.
        }

        connectedRecord?.core?.keyID?.let { keyID ->
            Log.d("BleService", "Starting background telemetry sync for: ${keyID.toHex()}")
            fastTxClient.syncTelemetry(BleProvider.getTransport(), keyID)
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

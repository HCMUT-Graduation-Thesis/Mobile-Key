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
import com.example.a100_basiccrypto.ui.home.HomeActivity
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransactionClient
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.shared.command.MessageConstants
import com.example.a100_basiccrypto.shared.link.IActiveTransport
import kotlinx.coroutines.*

/**
 * Foreground Service to maintain BLE connection and perform background telemetry sync.
 * Updated: Supports Local Revocation Phase for Owner-to-Friend management.
 */
class BleForegroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "ble_connection_channel"
        private const val NOTIFICATION_ID = 101
        private const val NORMAL_INTERVAL = 15000L 
        private const val FAST_INTERVAL = 3000L   
        const val ACTION_REFRESH_SCAN = "com.example.a100_basiccrypto.REFRESH_SCAN"
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var telemetryJob: Job? = null
    private var currentInterval = NORMAL_INTERVAL
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val authManager by lazy { AuthManager(this) }
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
                        BleProvider.getManager()?.closeEverything()
                        BleProvider.updateStatus("Bluetooth OFF")
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
                startTelemetryPolling() 
            }
        }
        
        startTelemetryPolling()
    }

    /**
     * OWNER SIDE: Executes any pending friend removal commands stored in the local queue.
     */
    private suspend fun processPendingRevocations(transport: IActiveTransport, ownerKeyID: ByteArray) {
        val pendingList = storageManager.getPendingRevocations(ownerKeyID)
        if (pendingList.isEmpty()) return

        Log.i("BleService", "⚙️ [REVOKE-LOCAL] Found ${pendingList.size} pending revocations. Executing...")
        pendingList.forEach { friendKeyID ->
            val status = fastTxClient.executeRemoveFriend(transport, ownerKeyID, friendKeyID)
            if (status == MessageConstants.Status.SUCCESS) {
                Log.i("BleService", "✅ [REVOKE-LOCAL] Friend ${friendKeyID.toHex()} successfully removed at Vehicle.")
                storageManager.removePendingRevocation(ownerKeyID, friendKeyID)
            } else {
                Log.e("BleService", "❌ [REVOKE-LOCAL] Failed to remove Friend ${friendKeyID.toHex()}. Status: $status")
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_REFRESH_SCAN) {
            Log.d("BleService", "Manual refresh scan requested. Forcing disconnect of old session...")
            BleProvider.getManager()?.closeEverything()
        }

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
        // Note: Even if isConnected() is true, refresh might have closed it above.
        if (manager == null) {
            Log.e("BleService", "BleCentralManager is null. Cannot trigger scan.")
            BleProvider.updateStatus("BLE service not initialized.")
            return
        }

        if (!manager.isConnected()) {
            val email = authManager.getUserEmail() ?: return

            // Optimized: Query keys directly by account from storage
            val keysToScan = storageManager.getKeysByAccount(email).filter {
                (it.core.keyState == KeyState.ACTIVE || it.core.keyState == KeyState.PROVISIONING) && 
                it.isAccessAllowedNow() // PROACTIVE: Only scan if validity is okay
            }

            if (keysToScan.isNotEmpty()) {
                Log.i("BleService", "Found ${keysToScan.size} valid keys for $email. Starting scan...")
                // Ưu tiên quét khóa đang PROVISIONING để hoàn tất pairing trước
                val targetKey = keysToScan.find { it.core.keyState == KeyState.PROVISIONING } ?: keysToScan[0]
                manager.scanAndConnect(targetKey)
            } else {
                Log.d("BleService", "No active or valid keys for $email. BLE staying idle.")
                BleProvider.updateStatus("No active or valid keys found.")
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
        val activeKeyID = manager?.connectedKeyID
        
        if (manager != null && manager.isConnected() && activeKeyID != null) {
            val currentEmail = authManager.getUserEmail()
            // Optimized: Get direct key by ID and verify ownership/validity
            val currentKey = storageManager.getDigitalKey(activeKeyID)
            
            if (currentKey == null || currentKey.accountEmail != currentEmail || !currentKey.isAccessAllowedNow()) {
                Log.w("BleService", "Active key invalid, expired or wrong account. Disconnecting...")
                manager.closeEverything()
                BleProvider.updateStatus("Access Denied - Disconnected")
                return
            }

            val transport = BleProvider.getTransport()
            if (transport != null) {
                // LOCAL PHASE: Process pending friend revocations before telemetry sync
                processPendingRevocations(transport, activeKeyID)

                val status = fastTxClient.syncTelemetry(transport, activeKeyID)
                if (status != null) {
                    withContext(Dispatchers.Main) {
                        BleProvider.notifyTelemetryUpdated(status)
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        BleProvider.setSyncTriggerListener(null)
        BleProvider.setPollingSpeedListener(null)
        unregisterReceiver(bluetoothReceiver)
        BleProvider.getManager()?.closeEverything() // Safe call here
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

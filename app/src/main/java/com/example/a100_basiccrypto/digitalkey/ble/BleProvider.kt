package com.example.a100_basiccrypto.digitalkey.ble

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.shared.model.VehicleStatus

/**
 * Singleton Provider - Now supports Sticky Vehicle Info and Telemetry updates.
 * Updated: Complete reset on logout to ensure account isolation.
 */
@SuppressLint("StaticFieldLeak")
object BleProvider {
    private var bleCentralManager: BleCentralManager? = null
    private var bleTransport: L2capActiveTransport? = null
    private var authManager: AuthManager? = null

    private val statusListeners = mutableSetOf<(String) -> Unit>()
    private val vehicleInfoListeners = mutableSetOf<(moduleID: String, mac: String, psm: Int) -> Unit>()
    private val telemetryListeners = mutableSetOf<(VehicleStatus) -> Unit>()
    private val connectionStateListeners = mutableSetOf<(Boolean) -> Unit>()
    
    private var onTriggerSyncRequest: (() -> Unit)? = null
    private var onSpeedChangeRequest: ((Boolean) -> Unit)? = null
    
    private var lastStatus: String = "BLE Idle"
    private var isCurrentlyConnected: Boolean = false
    
    // Sticky Cache
    private var lastVehicleInfo: Triple<String, String, Int>? = null
    private var lastTelemetry: VehicleStatus? = null

    fun init(appContext: Context) {
        val context = appContext.applicationContext
        
        // Always refresh AuthManager reference
        authManager = AuthManager(context)
        
        if (bleCentralManager == null) {
            bleCentralManager = BleCentralManager(context, authManager!!) { message ->
                Log.d("BLE_GLOBAL", message)
                updateStatus(message) // Use the new updateStatus method
            }
            bleTransport = L2capActiveTransport(bleCentralManager!!)
            
            bleCentralManager!!.onDataReceived = { data ->
                bleTransport!!.handleIncomingData(data)
            }

            bleCentralManager!!.onVehicleInfoUpdated = { mid, mac, psm ->
                lastVehicleInfo = Triple(mid, mac, psm)
                vehicleInfoListeners.forEach { it(mid, mac, psm) }
            }

            bleCentralManager!!.onConnectionStateChanged = { isConnected ->
                isCurrentlyConnected = isConnected
                connectionStateListeners.forEach { it(isConnected) }
            }
        }
    }

    /**
     * Public method to update the overall BLE status.
     */
    fun updateStatus(message: String) {
        lastStatus = message
        statusListeners.forEach { it(message) }
    }

    /**
     * Resets the BLE manager and clears all session data.
     * Call this during Logout to ensure account isolation.
     */
    fun logoutAndCleanup() {
        bleCentralManager?.closeEverything()
        bleCentralManager = null // Force re-creation on next login
        bleTransport = null
        lastVehicleInfo = null
        lastTelemetry = null
        isCurrentlyConnected = false
        updateStatus("BLE Logged Out") // Use the new updateStatus method
    }

    fun setSyncTriggerListener(listener: (() -> Unit)?) {
        onTriggerSyncRequest = listener
    }

    fun triggerImmediateSync() {
        onTriggerSyncRequest?.invoke()
    }

    fun setPollingSpeedListener(listener: ((Boolean) -> Unit)?) {
        onSpeedChangeRequest = listener
    }

    fun setFastPolling(enabled: Boolean) {
        onSpeedChangeRequest?.invoke(enabled)
    }

    fun notifyTelemetryUpdated(status: VehicleStatus) {
        lastTelemetry = status
        telemetryListeners.forEach { it(status) }
    }

    fun addStatusListener(listener: (String) -> Unit) {
        statusListeners.add(listener)
        listener(lastStatus)
    }

    fun removeStatusListener(listener: (String) -> Unit) {
        statusListeners.remove(listener)
    }

    fun addVehicleInfoListener(listener: (String, String, Int) -> Unit) {
        vehicleInfoListeners.add(listener)
        lastVehicleInfo?.let { (mid, mac, psm) ->
            listener(mid, mac, psm)
        }
    }

    fun removeVehicleInfoListener(listener: (String, String, Int) -> Unit) {
        vehicleInfoListeners.remove(listener)
    }

    fun addTelemetryListener(listener: (VehicleStatus) -> Unit) {
        telemetryListeners.add(listener)
        lastTelemetry?.let { listener(it) }
    }

    fun removeTelemetryListener(listener: (VehicleStatus) -> Unit) {
        telemetryListeners.remove(listener)
    }

    fun addConnectionStateListener(listener: (Boolean) -> Unit) {
        connectionStateListeners.add(listener)
        listener(isCurrentlyConnected)
    }

    fun removeConnectionStateListener(listener: (Boolean) -> Unit) {
        connectionStateListeners.remove(listener)
    }

    fun getManager(): BleCentralManager? = bleCentralManager // Now returns nullable
    fun getTransport(): L2capActiveTransport? = bleTransport // Now returns nullable
}

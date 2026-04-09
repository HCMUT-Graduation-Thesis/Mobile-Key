package com.example.a100_basiccrypto.digitalkey.ble

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import com.example.a100_basiccrypto.shared.model.VehicleStatus

/**
 * Singleton Provider - Now supports Sticky Vehicle Info and Telemetry updates.
 */
@SuppressLint("StaticFieldLeak")
object BleProvider {
    private var bleCentralManager: BleCentralManager? = null
    private var bleTransport: L2capActiveTransport? = null

    private val statusListeners = mutableSetOf<(String) -> Unit>()
    private val vehicleInfoListeners = mutableSetOf<(moduleID: String, mac: String, psm: Int) -> Unit>()
    private val telemetryListeners = mutableSetOf<(VehicleStatus) -> Unit>()
    
    private var lastStatus: String = "BLE Idle"
    
    // Sticky Cache
    private var lastVehicleInfo: Triple<String, String, Int>? = null
    private var lastTelemetry: VehicleStatus? = null

    fun init(appContext: Context) {
        if (bleCentralManager == null) {
            val context = appContext.applicationContext
            bleCentralManager = BleCentralManager(context) { message ->
                Log.d("BLE_GLOBAL", message)
                lastStatus = message
                
                if (message.contains("Link lost") || message.contains("OFF")) {
                    lastVehicleInfo = null
                    lastTelemetry = null
                }
                
                statusListeners.forEach { it(message) }
            }
            bleTransport = L2capActiveTransport(bleCentralManager!!)
            
            bleCentralManager!!.onDataReceived = { data ->
                bleTransport!!.handleIncomingData(data)
            }

            bleCentralManager!!.onVehicleInfoUpdated = { mid, mac, psm ->
                lastVehicleInfo = Triple(mid, mac, psm)
                vehicleInfoListeners.forEach { it(mid, mac, psm) }
            }
        }
    }

    /**
     * Broadcasts newly received vehicle telemetry data to all registered listeners.
     */
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

    fun getManager(): BleCentralManager = bleCentralManager!!
    fun getTransport(): L2capActiveTransport = bleTransport!!
}

package com.example.a100_basiccrypto.digitalkey.ble

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log

/**
 * Singleton Provider - Now supports Sticky Vehicle Info updates.
 */
@SuppressLint("StaticFieldLeak")
object BleProvider {
    private var bleCentralManager: BleCentralManager? = null
    private var bleTransport: L2capActiveTransport? = null

    private val statusListeners = mutableSetOf<(String) -> Unit>()
    private val vehicleInfoListeners = mutableSetOf<(moduleID: String, mac: String, psm: Int) -> Unit>()
    
    private var lastStatus: String = "BLE Idle"
    
    // Sticky Cache for the last identified vehicle info
    private var lastVehicleInfo: Triple<String, String, Int>? = null

    fun init(appContext: Context) {
        if (bleCentralManager == null) {
            val context = appContext.applicationContext
            bleCentralManager = BleCentralManager(context) { message ->
                Log.d("BLE_GLOBAL", message)
                lastStatus = message
                
                // If disconnected, clear sticky vehicle info
                if (message.contains("Link lost") || message.contains("OFF")) {
                    lastVehicleInfo = null
                }
                
                statusListeners.forEach { it(message) }
            }
            bleTransport = L2capActiveTransport(bleCentralManager!!)
            
            bleCentralManager!!.onDataReceived = { data ->
                bleTransport!!.handleIncomingData(data)
            }

            bleCentralManager!!.onVehicleInfoUpdated = { mid, mac, psm ->
                lastVehicleInfo = Triple(mid, mac, psm) // Cache the info
                vehicleInfoListeners.forEach { it(mid, mac, psm) }
            }
        }
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
        // Immediately trigger if we have cached info (Sticky behavior)
        lastVehicleInfo?.let { (mid, mac, psm) ->
            listener(mid, mac, psm)
        }
    }

    fun removeVehicleInfoListener(listener: (String, String, Int) -> Unit) {
        vehicleInfoListeners.remove(listener)
    }

    fun getManager(): BleCentralManager = bleCentralManager!!
    fun getTransport(): L2capActiveTransport = bleTransport!!
}

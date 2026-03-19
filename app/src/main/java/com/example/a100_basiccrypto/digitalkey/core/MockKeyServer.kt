package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * Mock Server to simulate Key Sharing between devices without real internet.
 * In a real app, this would be a Firebase/Retrofit service.
 */
object MockKeyServer {
    private const val TAG = "MockKeyServer"

    // Simulates a database of pending invitations on the server
    private var pendingAP: ByteArray? = null
    
    // Simulates Push Notification flow for Incoming Invitations
    private val _invitationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val invitationFlow = _invitationFlow.asSharedFlow()

    // Simulates Push Notification flow for Activation Success (Back to Owner)
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val activationFlow = _activationFlow.asSharedFlow()

    /**
     * Owner calls this to "upload" the Attestation Package to the server.
     */
    suspend fun uploadAP(ap: ByteArray): Boolean {
        Log.d(TAG, "Uploading AP to Mock Server (${ap.size} bytes)...")
        delay(1000) // Simulate network latency
        pendingAP = ap
        
        // In a real scenario, Server sends Push to Friend. 
        _invitationFlow.emit(ap)
        return true
    }

    /**
     * Friend calls this to "check" if there are any invitations for them.
     */
    suspend fun downloadAP(): ByteArray? {
        Log.d(TAG, "Checking for invitations on Mock Server...")
        delay(500)
        return pendingAP
    }

    /**
     * Friend calls this after successful Pairing/Activation at the Vehicle.
     * This notifies the Owner that the key is now Active.
     */
    suspend fun notifyActivation(ap: ByteArray) {
        Log.d(TAG, "Notifying Owner of Key Activation...")
        delay(500)
        _activationFlow.emit(ap)
    }

    /**
     * Clears the server state (for testing).
     */
    fun reset() {
        pendingAP = null
    }
}

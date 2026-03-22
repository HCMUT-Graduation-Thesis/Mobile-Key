package com.example.a100_basiccrypto.digitalkey.core

import android.util.Log
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * Data wrapper for a Key Invitation to include UI metadata without changing the AP.
 */
data class ShareInvitation(
    val ap: ByteArray,
    val friendlyName: String,
    val recipient: String = "",
    val senderName: String = "Owner"
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ShareInvitation
        return ap.contentEquals(other.ap) && friendlyName == other.friendlyName && recipient == other.recipient
    }

    override fun hashCode(): Int {
        var result = ap.contentHashCode()
        result = 31 * result + friendlyName.hashCode()
        result = 31 * result + recipient.hashCode()
        return result
    }
}

/**
 * Mock Server to simulate Key Sharing between devices without real internet.
 */
object MockKeyServer {
    private const val TAG = "MockKeyServer"

    // Simulates a database of pending invitations on the server
    private var pendingInvitation: ShareInvitation? = null
    
    // Simulates Push Notification flow for Incoming Invitations
    private val _invitationFlow = MutableSharedFlow<ShareInvitation>(replay = 0)
    val invitationFlow = _invitationFlow.asSharedFlow()

    // Simulates Push Notification flow for Activation Success (Back to Owner)
    private val _activationFlow = MutableSharedFlow<ByteArray>(replay = 0)
    val activationFlow = _activationFlow.asSharedFlow()

    /**
     * Owner calls this to "upload" the Attestation Package and Metadata to the server.
     */
    suspend fun uploadInvitation(invitation: ShareInvitation): Boolean {
        Log.d(TAG, "Uploading Invitation to Mock Server for ${invitation.recipient}...")
        delay(1000) // Simulate network latency
        pendingInvitation = invitation
        
        // In a real scenario, Server sends Push to Friend. 
        _invitationFlow.emit(invitation)
        return true
    }

    /**
     * Friend calls this to "check" if there are any invitations for them.
     */
    suspend fun downloadInvitation(): ShareInvitation? {
        Log.d(TAG, "Checking for invitations on Mock Server...")
        delay(500)
        return pendingInvitation
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
        pendingInvitation = null
    }
}

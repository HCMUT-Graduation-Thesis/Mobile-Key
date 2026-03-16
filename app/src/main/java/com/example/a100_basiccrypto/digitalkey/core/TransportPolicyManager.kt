package com.example.a100_basiccrypto.digitalkey.core

import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_TELEMETRY

/**
 * Manages which transport methods are allowed for specific command classes.
 * Updated to allow Standard/Admin transactions on both NFC and BLE.
 */
object TransportPolicyManager {

    // Define allowed transports per Logical Class
    private val policies: Map<Byte, TransportType> = mapOf(
        // Owner Pairing: Strictly NFC
        CLASS_OWNER_PAIRING  to TransportType.NFC,
        
        // Friend Pairing: Strictly BLE
        CLASS_FRIEND_PAIRING to TransportType.BLE,
        
        // Fast Actions & Engine Ops: Supported on both NFC and BLE
        CLASS_FAST_ACTION    to TransportType.BOTH,
        CLASS_ENGINE_OP      to TransportType.BOTH,
        
        // Admin (Standard Transaction): Allowed on BOTH for recovery and management
        CLASS_ADMIN          to TransportType.BOTH,
        
        // Telemetry: Strictly BLE
        CLASS_TELEMETRY      to TransportType.BLE
    )

    /**
     * Checks if a specific command class is allowed on the given transport.
     */
    fun isTransportAllowed(msgClass: Byte, currentTransport: TransportType): Boolean {
        // Special case: Custom codes (like 0x80) used in Pairing
        if (msgClass == 0x80.toByte()) return currentTransport == TransportType.NFC
        
        val allowed = policies[msgClass] ?: TransportType.BLE
        
        return when (allowed) {
            TransportType.BOTH -> true
            else -> allowed == currentTransport
        }
    }
}

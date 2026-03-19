package com.example.a100_basiccrypto.shared.policy

import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.shared.command.MessageConstants.CLASS_TELEMETRY

/**
 * Manages which transport methods are allowed for specific command classes.
 * This is a shared policy that both App and MCU must follow.
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
     * 
     * @param msgClass The logical class of the command.
     * @param currentTransport The transport being used (NFC or BLE).
     * @return true if allowed, false otherwise.
     */
    fun isTransportAllowed(msgClass: Byte, currentTransport: TransportType): Boolean {
        // Special case: Custom codes (like 0x80) used in Pairing flows
        if (msgClass == 0x80.toByte()) return currentTransport == TransportType.NFC
        
        val allowed = policies[msgClass] ?: TransportType.BLE
        
        return when (allowed) {
            TransportType.BOTH -> true
            else -> allowed == currentTransport
        }
    }
}

package com.example.a100_basiccrypto.digitalkey.core

import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ADMIN
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FAST_ACTION
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_ENGINE_OP
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_FRIEND_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_OWNER_PAIRING
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.CLASS_TELEMETRY

/**
 * Manages which transport methods are allowed for specific command classes.
 */
object TransportPolicyManager {

    private val policies: Map<Byte, TransportType> = mapOf(
        CLASS_FAST_ACTION    to TransportType.BOTH,
        CLASS_ENGINE_OP      to TransportType.NFC,
        CLASS_TELEMETRY      to TransportType.BOTH,
        CLASS_ADMIN          to TransportType.NFC,
        CLASS_OWNER_PAIRING  to TransportType.NFC,
        CLASS_FRIEND_PAIRING to TransportType.BOTH
    )

    /**
     * Checks if a specific command class is allowed on the given transport.
     */
    fun isTransportAllowed(msgClass: Byte, currentTransport: TransportType): Boolean {
        val allowed = policies[msgClass] ?: TransportType.BOTH
        return if (allowed == TransportType.BOTH) true else allowed == currentTransport
    }
}

package com.example.a100_basiccrypto.digitalkey.core

/**
 * Lifecycle states of a digital key.
 */
enum class KeyState(val value: Byte) {
    PROVISIONING(0x00), // During pairing process
    ACTIVE(0x01),       // Ready for use
    SUSPENDED(0x02),    // Temporarily disabled
    REVOKED(0x03),      // Permanently disabled/removed
    EXPIRED(0x04)       // Validity period ended
}

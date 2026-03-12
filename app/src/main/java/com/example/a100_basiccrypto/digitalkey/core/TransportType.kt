package com.example.a100_basiccrypto.digitalkey.core

/**
 * Supported communication transports for the digital key system.
 */
enum class TransportType(val value: Byte) {
    NFC(0x01),
    BLE(0x02),
    BOTH(0x03) // Used primarily in policies
}

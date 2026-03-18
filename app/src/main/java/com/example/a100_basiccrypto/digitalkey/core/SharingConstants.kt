package com.example.a100_basiccrypto.digitalkey.core

/**
 * Constants for Key Sharing and Attestation Package (AP) structure.
 */
object SharingConstants {
    // --- AP STRUCTURE VERSION ---
    const val AP_VERSION_V1 = 0x01.toByte()
    const val AP_VERSION_V2 = 0x02.toByte()

    // --- AP BINARY LAYOUT (Offsets) ---
    const val OFFSET_VERSION = 0
    const val OFFSET_PARENT_KEY_ID = 1
    const val OFFSET_INV_CODE_HASH = 9
    const val OFFSET_ROLE = 41
    const val OFFSET_PERMISSIONS = 42
    const val OFFSET_VALID_FROM = 46
    const val OFFSET_VALID_TO = 54

    // New Fields in V2
    const val OFFSET_USAGE_LIMIT = 62    // 1 byte
    const val OFFSET_DAYS_OF_WEEK = 63   // 1 byte (bitmask)
    const val OFFSET_START_TIME = 64     // 2 bytes (Short)
    const val OFFSET_END_TIME = 66       // 2 bytes (Short)

    const val METADATA_SIZE = 68         // Total bytes before Signature
    const val OFFSET_SIGNATURE = 68

    // --- PERMISSION BITS ---
    const val PERM_UNLOCK  = 0x00000001
    const val PERM_LOCK    = 0x00000002
    const val PERM_START   = 0x00000004
    const val PERM_TRUNK   = 0x00000008
    const val PERM_PANIC   = 0x00000010
}

package com.example.a100_basiccrypto.digitalkey.core

data class DigitalKeyRecord(
    // 1. Identification Data
    var keyID: ByteArray? = null, // 16 bytes
    var moduleID: ByteArray? = null, // 16 bytes
    var slotID: Byte = 0, // 1 byte

    // 2. Cryptographic & Security Data
    var devicePublicKey: ByteArray? = null, // ~1952 bytes (Dilithium 3)
    var vehiclePublicKey: ByteArray? = null, // ~1952 bytes (Dilithium 3)
    var fastAuthKey: ByteArray? = null, // 32 bytes
    var immobilizerToken: ByteArray? = null, // 64 bytes

    // 3. Transaction Data
    var transactionCounter: Int = 0,
    var lastCounter: Int = 0,

    // 4. Lifecycle & Permissions Data
    var role: Role = Role.OWNER,
    var permissions: Int = 0, // Bitmask
    var validityStart: Long = 0L, // Timestamp
    var validityEnd: Long = 0L, // Timestamp
    var parentKeyID: ByteArray? = null,

    // 5. State & Management Data
    var keyState: KeyState = KeyState.UNPAIRED,
    var friendlyName: String = ""
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DigitalKeyRecord
        return keyID.contentEquals(other.keyID)
    }

    override fun hashCode(): Int {
        return keyID?.contentHashCode() ?: 0
    }
}

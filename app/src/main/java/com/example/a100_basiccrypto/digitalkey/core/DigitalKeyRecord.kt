package com.example.a100_basiccrypto.digitalkey.core

/**
 * Main data model for a digital key.
 * Contains all security tokens, keys, and metadata.
 */
data class DigitalKeyRecord(
    // 1. Identification Data
    var keyID: ByteArray? = null,
    var moduleID: ByteArray? = null,
    var slotID: Byte = 0,
    var accountID: String? = null, // Link to User Account

    // 2. Cryptographic & Security Data
    var devicePublicKey: ByteArray? = null,
    var vehiclePublicKey: ByteArray? = null,
    var fastAuthKey: ByteArray? = null,
    var immobilizerToken: ByteArray? = null,

    // 3. Transaction Data
    var transactionCounter: Int = 0,
    var lastCounter: Int = 0,

    // 4. Lifecycle & Permissions Data
    var role: Role = Role.OWNER,
    var permissions: Int = 0,
    var validityStart: Long = 0L,
    var validityEnd: Long = 0L,
    var parentKeyID: ByteArray? = null,

    // 5. State & Management Data
    var keyState: KeyState = KeyState.PROVISIONING,
    var syncStatus: SyncStatus = SyncStatus.PENDING_UPLOAD,
    var friendlyName: String = "",
    var carMetadata: CarMetadata? = null
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

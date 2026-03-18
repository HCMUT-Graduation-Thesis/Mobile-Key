package com.example.a100_basiccrypto.digitalkey.core

import java.util.Calendar

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
    var devicePrivateKey: ByteArray? = null, // Unique Private Key per vehicle for privacy
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

    // --- New Sharing Features ---
    var usageLimit: Int = 0,         // 0 = Unlimited, 1 = One-time, etc.
    var currentUsageCount: Int = 0,
    var daysOfWeek: Int = 0,         // Bitmask (Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64)
    var startTimeMinutes: Int = -1,  // Minutes from midnight (0-1439), -1 = All day
    var endTimeMinutes: Int = -1,    // Minutes from midnight (0-1439), -1 = All day

    // 5. State & Management Data
    var keyState: KeyState = KeyState.PROVISIONING,
    var syncStatus: SyncStatus = SyncStatus.PENDING_UPLOAD,
    var friendlyName: String = "",
    var carMetadata: CarMetadata? = null,

    // 6. Sharing & Attestation Data
    var attestationPackage: ByteArray? = null, // The signed blob for Friend Pairing
    var invitationCodeHash: ByteArray? = null, // SHA-256 of the invitation code
    var invitationCode: String? = null         // Plain code (Stored only on Owner device for sharing)
) {
    /**
     * Checks if the key is currently allowed to perform an action based on time/usage constraints.
     */
    fun isAccessAllowedNow(): Boolean {
        val now = System.currentTimeMillis() / 1000

        // 1. Timed Check (Start/End)
        if (validityStart > 0 && now < validityStart) return false
        if (validityEnd > 0 && now > validityEnd) return false

        // 2. One-time Check (Usage Limit)
        if (usageLimit > 0 && currentUsageCount >= usageLimit) return false

        // 3. Recurring Check (Day of week & Time of day)
        if (daysOfWeek != 0 || startTimeMinutes != -1) {
            val calendar = Calendar.getInstance()
            
            // dayOfWeek: 1 (Sun) to 7 (Sat)
            val day = calendar.get(Calendar.DAY_OF_WEEK)
            val bit = 1 shl (day - 1)
            if (daysOfWeek != 0 && (daysOfWeek and bit) == 0) return false

            val currentMinutes = calendar.get(Calendar.HOUR_OF_DAY) * 60 + calendar.get(Calendar.MINUTE)
            if (startTimeMinutes != -1 && currentMinutes < startTimeMinutes) return false
            if (endTimeMinutes != -1 && currentMinutes > endTimeMinutes) return false
        }

        return true
    }

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

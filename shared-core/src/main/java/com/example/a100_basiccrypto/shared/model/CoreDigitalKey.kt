package com.example.a100_basiccrypto.shared.model

import java.util.Calendar

/**
 * CoreDigitalKey represents the "Single Source of Truth" shared between 
 * the mobile device (App) and the vehicle (MCU).
 */
data class CoreDigitalKey(
    // 1. Identification Data
    var devicePublicKey: ByteArray? = null,
    var vehiclePublicKey: ByteArray? = null, // The Vehicle's Public Key for verification
    var keyID: ByteArray? = null,
    var moduleID: ByteArray? = null,
    var slotID: Byte = 0,
    var role: Role = Role.OWNER,

    // 2. Cryptographic Secrets
    var fastAuthKey: ByteArray? = null,       // Symmetric key for HMAC/Fast Auth
    var immobilizerToken: ByteArray? = null, // Token required to start engine

    // 3. Status & Permissions & Chain of Trust
    var keyState: KeyState = KeyState.ACTIVE,
    var permissions: Int = 0,
    var parentKeyID: ByteArray? = null,

    // 4. Counter and Usage Count
    var transactionCounter: Int = 0,        // Counter to prevent Replay Attacks
    var currentUsageCount: Int = 0,          // Local count of successful transactions

    // 5. Validity & Constraints (The "Contract")
    var validityStart: Long = 0L,      // Timestamp in seconds (Unix Time)
    var validityEnd: Long = 0L,        // Timestamp in seconds (Unix Time)
    var usageLimit: Int = 0,          // 0 = Unlimited, >0 = Limited use
    var daysOfWeek: Int = 0,          // Bitmask (Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64)
    var startTimeMinutes: Int = -1,    // Minutes from midnight (0-1439), -1 = All day
    var endTimeMinutes: Int = -1,       // Minutes from midnight (0-1439), -1 = All day
    
    // 6. Vehicle Identity
    var carMetadata: CarMetadata? = null
) {
    /**
     * Enforces access control based on time, usage, and recurring schedule.
     */
    fun isAccessAllowedNow(): Boolean {
        val now = System.currentTimeMillis() / 1000

        // 1. Global Validity Period Check
        if (validityStart > 0 && now < validityStart) return false
        if (validityEnd > 0 && now > validityEnd) return false

        // 2. Usage Limit Check
        if (usageLimit > 0 && currentUsageCount >= usageLimit) return false

        // 3. Recurring Schedule Check
        if (daysOfWeek != 0 || startTimeMinutes != -1) {
            val calendar = Calendar.getInstance()
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
        other as CoreDigitalKey
        return keyID.contentEquals(other.keyID)
    }

    override fun hashCode(): Int {
        return keyID?.contentHashCode() ?: 0
    }
}

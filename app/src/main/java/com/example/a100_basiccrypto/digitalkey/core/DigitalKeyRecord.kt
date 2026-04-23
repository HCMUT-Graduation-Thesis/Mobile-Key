package com.example.a100_basiccrypto.digitalkey.core

import com.example.a100_basiccrypto.shared.model.CoreDigitalKey
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.CarMetadata
import com.example.a100_basiccrypto.shared.model.SyncStatus
import com.example.a100_basiccrypto.shared.model.VehicleStatus

/**
 * DigitalKeyRecord is the App-specific data model for a digital key.
 */
data class DigitalKeyRecord(
    // 1. Core "Contract" Data (The Single Source of Truth shared with MCU)
    var core: CoreDigitalKey = CoreDigitalKey(),

    // 2. App-Specific Identification & Cloud Metadata
    var accountEmail: String? = null, // Link to User Account (Email)

    // 3. App-Specific Secrets & Identity
    var devicePublicKey: ByteArray? = null,  // Dilithium PK of the App
    var vehiclePublicKey: ByteArray? = null, // Dilithium PK of the Vehicle
    var devicePrivateKey: ByteArray? = null, // Unique Private Key per vehicle
    var immobilizerToken: ByteArray? = null, // Token for BLE PSM decryption & Engine Start
    var carMetadata: CarMetadata? = null,    // Vehicle Identity (App-only storage)
    var moduleID: ByteArray? = null,         // Unique ID of the vehicle module

    // 4. Lifecycle & UI Metadata
    var syncStatus: SyncStatus = SyncStatus.PENDING_UPLOAD,
    var friendlyName: String = "",

    // 5. Sharing & Attestation Data (Used during provisioning flows)
    var attestationPackage: ByteArray? = null, // The signed blob for Friend Pairing
    var invitationCodeHash: ByteArray? = null, // SHA-256 of the invitation code
    var invitationCode: String? = null,        // Plain code

    // 6. Local usage count to enforce limits independently
    var currentUsageCount: Int = 0,

    // 7. Last known vehicle physical status (Telemetry)
    var vehicleStatus: VehicleStatus? = null
) {
    /**
     * Delegates the access control check to the Core model.
     */
    fun isAccessAllowedNow(): Boolean {
        // Sync the local usage count to core before checking
        core.currentUsageCount = currentUsageCount
        return core.isAccessAllowedNow()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DigitalKeyRecord
        return core.keyID.contentEquals(other.core.keyID)
    }

    override fun hashCode(): Int {
        return core.keyID?.contentHashCode() ?: 0
    }
}

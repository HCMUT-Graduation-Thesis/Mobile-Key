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
    // 1. Core "Contract" Data
    var core: CoreDigitalKey = CoreDigitalKey(),

    // 2. App-Specific Identification & Cloud Metadata
    var accountEmail: String? = null, 

    // 3. App-Specific Secrets & Identity
    var devicePublicKey: ByteArray? = null,  
    var vehiclePublicKey: ByteArray? = null, 
    var devicePrivateKey: ByteArray? = null, 
    var immobilizerToken: ByteArray? = null, 
    var carMetadata: CarMetadata? = null,    
    var moduleID: ByteArray? = null,         

    // 4. Lifecycle & UI Metadata
    var syncStatus: SyncStatus = SyncStatus.PENDING_UPLOAD,
    var friendlyName: String = "",       // Car's Friendly Name (e.g. "My VF8")
    var keyHolderName: String = "",     // NEW: Holder's Nickname (e.g. "John's Key")

    // 5. Sharing & Attestation Data
    var attestationPackage: ByteArray? = null, 
    var invitationCodeHash: ByteArray? = null, 
    var invitationCode: String? = null,        
    var invitationId: String? = null, // Store cloud invitation ID for reporting

    // 6. Local usage count
    var currentUsageCount: Int = 0,

    // 7. Last known vehicle physical status
    var vehicleStatus: VehicleStatus? = null
) {
    fun isAccessAllowedNow(): Boolean {
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

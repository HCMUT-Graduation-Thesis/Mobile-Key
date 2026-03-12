package com.example.a100_basiccrypto.digitalkey.core

/**
 * UNIFIED LOGICAL COMMAND SET V2.1
 * Transport Agnostic Format: [CLASS (1b)] [INS (1b)] [LENGTH (2b)] [DATA (Nb)]
 */
object MessageConstants {

    // --- LOGICAL CLASSES (Security Context & Routing Group) ---
    const val CLASS_FAST_ACTION      = 0x10.toByte() // Fast Auth (HMAC/AES-GCM)
    const val CLASS_ENGINE_OP        = 0x20.toByte() // Engine start/stop (Token required)
    const val CLASS_TELEMETRY        = 0x30.toByte() // Status & Vehicle Info
    const val CLASS_ADMIN            = 0x40.toByte() // High Sensitive (PQC Signature required)
    const val CLASS_OWNER_PAIRING    = 0x50.toByte() // Owner Provisioning Flow
    const val CLASS_FRIEND_PAIRING   = 0x60.toByte() // Friend Provisioning Flow

    // --- CLASS 0x10: Basic Access (INS) ---
    const val INS_UNLOCK             = 0x01.toByte()
    const val INS_LOCK               = 0x02.toByte()
    const val INS_OPEN_TRUNK         = 0x03.toByte()
    const val INS_REMOVE_FRIEND      = 0x04.toByte()

    // --- CLASS 0x20: Engine Operation (INS) ---
    const val INS_START_ENGINE       = 0x01.toByte()
    const val INS_STOP_ENGINE        = 0x02.toByte()

    // --- CLASS 0x30: Telemetry (INS) ---
    const val INS_GET_STATUS         = 0x01.toByte()
    const val INS_GET_BATTERY        = 0x02.toByte()
    const val INS_GET_VEHICLE_INFO   = 0x03.toByte()

    // --- CLASS 0x40: Admin Commands (INS) ---
    const val INS_REVOKE_OWNER       = 0x01.toByte()
    const val INS_FACTORY_RESET      = 0x02.toByte()

    // --- CLASS 0x50: Owner Provisioning Phases (INS) ---
    const val PHASE_PAIRING_REQ      = 0x11.toByte()
    const val PHASE_KEY_EXCHANGE     = 0x13.toByte()
    const val PHASE_VERIFY_NONCE     = 0x15.toByte()
    const val PHASE_DATA_SYNC        = 0x19.toByte()
    const val PHASE_COMMIT           = 0x17.toByte()

    // --- CLASS 0x60: Friend Provisioning Phases (INS) ---
    const val PHASE_FRIEND_INIT      = 0x11.toByte()
    const val PHASE_FRIEND_ECDH      = 0x13.toByte()
    const val PHASE_VERIFY_ATTEST    = 0x21.toByte() // Verify Owner's Attestation Package
    const val PHASE_FRIEND_POP       = 0x23.toByte() // Proof of Possession (PQC Signature)
    const val PHASE_FRIEND_PROV      = 0x19.toByte() // Receive Token & SlotID
    const val PHASE_FRIEND_COMMIT    = 0x17.toByte()

    // --- GLOBAL STATUS & ERRORS ---
    const val MSG_GLOBAL_SUCCESS     = 0x90.toByte()
    const val MSG_ERR_GENERAL        = 0xE0.toByte()
    const val MSG_ERR_AUTH_FAIL      = 0xE2.toByte()
    const val MSG_ERR_INVALID_CLASS  = 0xE7.toByte()
    const val MSG_ERR_PERMISSION     = 0xE8.toByte()
}

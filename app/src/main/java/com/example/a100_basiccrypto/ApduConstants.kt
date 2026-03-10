package com.example.a100_basiccrypto

object ApduConstants {
    // Command Header (CLA, INS)
    const val CLA_ISO = 0x00.toByte()
    const val CLA_PROPRIETARY = 0x80.toByte()
    const val INS_SELECT_AID = 0xA4.toByte()          // Phase 1
    const val INS_EXCHANGE_AND_DERIVE = 0x10.toByte() // Phase 2.a
    const val INS_VERIFY_NONCE = 0x20.toByte()        // Phase 2.b
    const val INS_EXCHANGE_IMMOBILIZER = 0x30.toByte() // Phase 3
    const val INS_COMMIT_PAIRING = 0x40.toByte()       // Phase 4
    
    // AES-GCM Constants
    const val AES_GCM_IV_LENGTH = 12
    const val AES_GCM_TAG_LENGTH = 16 // bytes (128 bits)
    
    // Status Words (SW)
    val SW_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
    val SW_UNKNOWN_CMD = byteArrayOf(0x6D.toByte(), 0x00.toByte())
    val SW_WRONG_LENGTH = byteArrayOf(0x67.toByte(), 0x00.toByte())
    val SW_WRONG_PASSWORD = byteArrayOf(0x63.toByte(), 0x00.toByte())
    val SW_DECRYPTION_FAILED = byteArrayOf(0x63.toByte(), 0x03.toByte())
    val SW_DATA_MISMATCH = byteArrayOf(0x63.toByte(), 0x04.toByte())
    val SW_INTERNAL_ERROR = byteArrayOf(0x6F.toByte(), 0x00.toByte())
    
    const val AID = "F0010203040506"
}

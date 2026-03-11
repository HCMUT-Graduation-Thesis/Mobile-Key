package com.example.a100_basiccrypto.digitalkey.nfc

object ApduConstants {
    // Application ID (AID)
    const val AID_HCE = "F0010203040506"

    // Command Header (CLA, INS)
    const val CLA_ISO = 0x00.toByte()
    const val CLA_PROPRIETARY = 0x80.toByte()
    const val INS_SELECT_AID = 0xA4.toByte()          // Phase 1
    const val INS_EXCHANGE_AND_DERIVE = 0x10.toByte() // Phase 2.a
    const val INS_VERIFY_NONCE = 0x20.toByte()        // Phase 2.b
    const val INS_EXCHANGE_IMMOBILIZER = 0x30.toByte() // Phase 3 (Reader -> HCE)
    const val INS_GET_NEXT_CHUNK = 0x31.toByte()       // Phase 3 (HCE -> Reader)
    const val INS_COMMIT_PAIRING = 0x40.toByte()       // Phase 4

    // Chaining Configuration
    const val MAX_APDU_PAYLOAD_SIZE = 200

    // System Configuration & AES-GCM
    const val AES_GCM_IV_LENGTH = 12
    const val AES_GCM_TAG_LENGTH = 16 // bytes
    const val TRANSACTION_TIMEOUT_MS = 10000L // 10 seconds

    // Status Words (SW)
    val SW_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
    val SW_HAS_MORE_DATA = byteArrayOf(0x90.toByte(), 0x01.toByte())
    val SW_UNKNOWN_CMD = byteArrayOf(0x6D.toByte(), 0x00.toByte())
    val SW_DECRYPTION_FAILED = byteArrayOf(0x63.toByte(), 0x03.toByte())
    val SW_DATA_MISMATCH = byteArrayOf(0x63.toByte(), 0x04.toByte())
    val SW_TIMEOUT = byteArrayOf(0x68.toByte(), 0x00.toByte())
    val SW_INTERNAL_ERROR = byteArrayOf(0x6F.toByte(), 0x00.toByte())
}

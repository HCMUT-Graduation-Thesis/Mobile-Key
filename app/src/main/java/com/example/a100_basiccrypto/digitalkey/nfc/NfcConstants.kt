package com.example.a100_basiccrypto.digitalkey.nfc

/**
 * NFC and APDU related constants.
 */
object NfcConstants {
    const val AID_HCE = "F0010203040506"
    const val CLA_ISO = 0x00.toByte()
    const val CLA_PROPRIETARY = 0x80.toByte()
    
    // Status Words (SW)
    val SW_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
    val SW_HAS_MORE_DATA = byteArrayOf(0x90.toByte(), 0x01.toByte())
    val SW_UNKNOWN_CMD = byteArrayOf(0x6D.toByte(), 0x00.toByte())
    val SW_DECRYPTION_FAILED = byteArrayOf(0x63.toByte(), 0x03.toByte())
    val SW_DATA_MISMATCH = byteArrayOf(0x63.toByte(), 0x04.toByte())
    val SW_TIMEOUT = byteArrayOf(0x68.toByte(), 0x00.toByte())
    val SW_INTERNAL_ERROR = byteArrayOf(0x6F.toByte(), 0x00.toByte())

    const val MAX_APDU_PAYLOAD_SIZE = 200
    const val TRANSACTION_TIMEOUT_MS = 10000L
    
    // Đổi từ 0x01 sang 0xFF để tránh trùng với INS_UNLOCK
    const val INS_GET_NEXT_CHUNK = 0xFF.toByte()
}

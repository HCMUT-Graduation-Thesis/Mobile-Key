package com.example.a100_basiccrypto.digitalkey.core

enum class KeyState(val value: Byte) {
    UNPAIRED(0x00),
    PAIRED(0x01),
    ACTIVE(0x02),
    SUSPENDED(0x03),
    REVOKED(0x04)
}

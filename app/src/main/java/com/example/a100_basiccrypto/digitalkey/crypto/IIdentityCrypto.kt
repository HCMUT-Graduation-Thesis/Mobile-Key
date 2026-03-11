package com.example.a100_basiccrypto.digitalkey.crypto

/**
 * Interface for long-term identity crypto operations.
 */
interface IIdentityCrypto {
    fun getPublicKey(): ByteArray
    fun getPrivateKey(): ByteArray
}

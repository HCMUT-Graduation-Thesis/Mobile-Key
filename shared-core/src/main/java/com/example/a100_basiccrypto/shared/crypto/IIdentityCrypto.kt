package com.example.a100_basiccrypto.shared.crypto

/**
 * Interface for long-term identity crypto operations.
 * Shared between Mobile App and Vehicle.
 */
interface IIdentityCrypto {
    fun getPublicKey(): ByteArray
    fun getPrivateKey(): ByteArray
    
    // Support signing and verification for Standard Transaction
    fun sign(data: ByteArray, privateKeyBytes: ByteArray): ByteArray
    fun verify(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean
}

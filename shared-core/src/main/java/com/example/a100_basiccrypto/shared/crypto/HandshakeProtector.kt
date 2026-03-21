package com.example.a100_basiccrypto.shared.crypto

import java.security.*
import java.security.interfaces.ECPublicKey
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.normalize

/**
 * High-level orchestration for ECDH Handshake and Session Key derivation.
 * Leverages CryptoUtils for low-level primitive operations.
 */
object HandshakeProtector {

    /**
     * Step 1: Generate Ephemeral KeyPair for the current session.
     */
    fun generateEphemeralKeyPair(): KeyPair {
        return CryptoUtils.generateEcKeyPair()
    }

    /**
     * Step 2: Format EC Public Key into raw uncompressed bytes (65 bytes).
     * Format: [0x04] [X (32b)] [Y (32b)]
     */
    fun getRawUncompressedPublicKey(publicKey: PublicKey): ByteArray {
        val ecPubKey = publicKey as ECPublicKey
        val x = ecPubKey.w.affineX.toByteArray().normalize(32)
        val y = ecPubKey.w.affineY.toByteArray().normalize(32)
        return byteArrayOf(0x04.toByte()) + x + y
    }

    /**
     * Step 3: Parse raw uncompressed bytes (65 bytes) back into a PublicKey object.
     */
    fun parseUncompressedPublicKey(data: ByteArray): PublicKey {
        return CryptoUtils.getPublicKeyFromBytes(data)
    }

    /**
     * Step 4: Derive Session Key from Shared Secret using HKDF.
     */
    fun deriveSessionKey(
        myPrivate: PrivateKey,
        otherPublic: PublicKey,
        salt: ByteArray,
        info: String
    ): ByteArray {
        val sharedSecret = CryptoUtils.generateSharedSecret(myPrivate, otherPublic)
        return CryptoUtils.deriveSessionKey(sharedSecret, salt, info.toByteArray(), 32)
    }
}

package com.example.a100_basiccrypto.shared.crypto

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Low-level cryptographic utility object.
 * Serves as the foundation for all security operations in the system.
 */
object CryptoUtils {

    private const val CURVE_NAME = "secp256r1"
    private const val EC_ALGORITHM = "EC"
    private const val ECDH_ALGORITHM = "ECDH"
    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val SHA256_ALGORITHM = "SHA-256"
    private const val AES_GCM_ALGORITHM = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_IV_LENGTH = 12

    /**
     * Generates a new EC KeyPair using the standard curve.
     */
    fun generateEcKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance(EC_ALGORITHM)
        kpg.initialize(ECGenParameterSpec(CURVE_NAME))
        return kpg.generateKeyPair()
    }

    /**
     * Converts raw uncompressed bytes (65 bytes) to a PublicKey object.
     */
    fun getPublicKeyFromBytes(pubBytes: ByteArray): PublicKey {
        if (pubBytes.size != 65 || pubBytes[0] != 0x04.toByte()) {
            throw IllegalArgumentException("Invalid Uncompressed Public Key format")
        }
        val x = BigInteger(1, pubBytes.sliceArray(1..32))
        val y = BigInteger(1, pubBytes.sliceArray(33..64))
        val point = ECPoint(x, y)
        val keySpec = ECPublicKeySpec(point, getParameterSpec())
        val kf = KeyFactory.getInstance(EC_ALGORITHM)
        return kf.generatePublic(keySpec)
    }

    fun String.hexToBytes(): ByteArray {
        val len = length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) +
                    Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }.uppercase()
    }

    fun sha256(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(SHA256_ALGORITHM)
        return md.digest(data)
    }

    fun getPrivateKeyFromHex(hexPriv: String): PrivateKey {
        val privBytes = hexPriv.hexToBytes()
        val keySpec = ECPrivateKeySpec(BigInteger(1, privBytes), getParameterSpec())
        val kf = KeyFactory.getInstance(EC_ALGORITHM)
        return kf.generatePrivate(keySpec)
    }

    fun getPublicKeyFromHex(hexPub: String): PublicKey {
        return getPublicKeyFromBytes(hexPub.hexToBytes())
    }

    fun generateSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(ECDH_ALGORITHM)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    fun deriveSessionKey(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmac(salt, ikm)
        val result = ByteArray(length)
        var lastT = ByteArray(0)
        var offset = 0
        var blockIndex = 1
        while (offset < length) {
            val input = lastT + info + byteArrayOf(blockIndex.toByte())
            lastT = hmac(prk, input)
            val bytesToCopy = minOf(lastT.size, length - offset)
            System.arraycopy(lastT, 0, result, offset, bytesToCopy)
            offset += bytesToCopy
            blockIndex++
        }
        return result
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(data)
    }

    private fun getParameterSpec(): ECParameterSpec {
        val algorithmParameters = AlgorithmParameters.getInstance(EC_ALGORITHM)
        algorithmParameters.init(ECGenParameterSpec(CURVE_NAME))
        return algorithmParameters.getParameterSpec(ECParameterSpec::class.java)
    }

    fun encryptAesGcm(plainText: ByteArray, sessionKey: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM_ALGORITHM)
        val iv = ByteArray(GCM_IV_LENGTH).apply { SecureRandom().nextBytes(this) }
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), spec)
        val ciphertext = cipher.doFinal(plainText)
        return iv + ciphertext
    }

    fun decryptAesGcm(cipherData: ByteArray, sessionKey: ByteArray): ByteArray {
        val iv = cipherData.sliceArray(0 until GCM_IV_LENGTH)
        val ciphertext = cipherData.sliceArray(GCM_IV_LENGTH until cipherData.size)
        val cipher = Cipher.getInstance(AES_GCM_ALGORITHM)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), spec)
        return cipher.doFinal(ciphertext)
    }

    fun ByteArray.normalize(size: Int): ByteArray {
        if (this.size == size) return this
        if (this.size > size) return this.sliceArray(this.size - size until this.size)
        val res = ByteArray(size)
        System.arraycopy(this, 0, res, size - this.size, this.size)
        return res
    }
}

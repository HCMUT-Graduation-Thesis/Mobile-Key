package com.example.a100_basiccrypto.shared.crypto

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import java.security.SecureRandom

/**
 * Implementation of ML-DSA-65 (FIPS 204 Standard).
 * Compatible with ML-DSA on ESP32 (3309 bytes signature).
 */
class DilithiumIdentityCryptoImpl : IIdentityCrypto {

    // Using ML-DSA-65 (Equivalent to Dilithium3 but FIPS 204 standard)
    private val params = MLDSAParameters.ml_dsa_65
    private val publicKeyParams: MLDSAPublicKeyParameters
    private val privateKeyParams: MLDSAPrivateKeyParameters

    init {
        val engine = MLDSAKeyPairGenerator()
        engine.init(MLDSAKeyGenerationParameters(SecureRandom(), params))
        val pair = engine.generateKeyPair()
        publicKeyParams = pair.public as MLDSAPublicKeyParameters
        privateKeyParams = pair.private as MLDSAPrivateKeyParameters
        println("ML-DSACrypto: Low-level ML-DSA-65 Engine Initialized")
    }

    override fun getPublicKey(): ByteArray {
        // Returns exactly 1952 bytes
        return publicKeyParams.encoded
    }

    override fun getPrivateKey(): ByteArray {
        // ML-DSA-65 SK is 4032 bytes
        return privateKeyParams.encoded
    }

    override fun sign(data: ByteArray, privateKeyBytes: ByteArray): ByteArray {
        return try {
            val privKey = MLDSAPrivateKeyParameters(params, privateKeyBytes)
            val signer = MLDSASigner()
            signer.init(true, privKey)
            signer.update(data, 0, data.size)
            signer.generateSignature()
        } catch (e: Exception) {
            println("ML-DSACrypto: Sign error: ${e.message}")
            ByteArray(0)
        }
    }

    override fun verify(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean {
        return try {
            val rawPubKey = if (publicKeyBytes.size > 1952) {
                publicKeyBytes.takeLast(1952).toByteArray()
            } else {
                publicKeyBytes
            }

            if (rawPubKey.size != 1952) {
                println("ML-DSACrypto: Invalid Public Key size: ${rawPubKey.size}")
                return false
            }

            // ML-DSA-65 signature must be 3309 bytes
            if (signature.size != 3309) {
                println("ML-DSACrypto: WARNING - Invalid signature size! (Received: ${signature.size}, Required: 3309)")
            }

            val pubKey = MLDSAPublicKeyParameters(params, rawPubKey)
            val verifier = MLDSASigner()
            verifier.init(false, pubKey)

            verifier.update(data, 0, data.size)
            val result = verifier.verifySignature(signature)
            if (!result) {
                println("ML-DSACrypto: Math Verification Failed!")
            }
            result
        } catch (e: Exception) {
            println("ML-DSACrypto: Verify exception: ${e.message}")
            false
        }
    }
}

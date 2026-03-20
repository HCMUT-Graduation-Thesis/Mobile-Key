package com.example.a100_basiccrypto.shared.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Implementation of ML-DSA (Standardized Dilithium) Crypto 
 * using the BouncyCastle provider instance directly.
 * Shared between Mobile App and Vehicle.
 */
class DilithiumIdentityCryptoImpl : IIdentityCrypto {

    private val bcProvider: Provider = BouncyCastleProvider()
    private val keyPair: KeyPair

    init {
        try {
            // Use "ML-DSA" instead of "Dilithium" for standardization
            val kpg = KeyPairGenerator.getInstance("ML-DSA", bcProvider)
            
            // dilithium3 corresponds to ml_dsa_65 as per FIPS 204
            kpg.initialize(MLDSAParameterSpec.ml_dsa_65, SecureRandom())

            keyPair = kpg.generateKeyPair()
        } catch (e: Exception) {
            println("DilithiumCrypto: Init failed: ${e.message}")
            throw RuntimeException("Failed to initialize ML-DSA KeyPairGenerator", e)
        }
    }

    override fun getPublicKey(): ByteArray {
        return keyPair.public.encoded
    }

    override fun getPrivateKey(): ByteArray {
        return keyPair.private.encoded
    }

    override fun sign(data: ByteArray, privateKeyBytes: ByteArray): ByteArray {
        return try {
            val kf = KeyFactory.getInstance("ML-DSA", bcProvider)
            val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            val signer = Signature.getInstance("ML-DSA", bcProvider)
            signer.initSign(privateKey)
            signer.update(data)
            signer.sign()
        } catch (e: Exception) {
            println("DilithiumCrypto: Sign failed: ${e.message}")
            ByteArray(0)
        }
    }

    override fun verify(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean {
        return try {
            val kf = KeyFactory.getInstance("ML-DSA", bcProvider)
            val publicKey = kf.generatePublic(X509EncodedKeySpec(publicKeyBytes))

            val verifier = Signature.getInstance("ML-DSA", bcProvider)
            verifier.initVerify(publicKey)
            verifier.update(data)
            verifier.verify(signature)
        } catch (e: Exception) {
            println("DilithiumCrypto: Verify error: ${e.message}")
            false
        }
    }
}

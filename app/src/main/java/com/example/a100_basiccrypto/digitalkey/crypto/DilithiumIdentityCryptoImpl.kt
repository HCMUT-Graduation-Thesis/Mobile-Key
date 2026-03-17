package com.example.a100_basiccrypto.digitalkey.crypto

import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Implementation of Dilithium Crypto using the BouncyCastle provider instance directly.
 */
class DilithiumIdentityCryptoImpl : IIdentityCrypto {

    private val bcProvider: Provider = BouncyCastleProvider()
    private val keyPair: KeyPair

    init {
        try {
            val kpg = KeyPairGenerator.getInstance("Dilithium", bcProvider)
            kpg.initialize(DilithiumParameterSpec.dilithium3, SecureRandom())
            keyPair = kpg.generateKeyPair()
        } catch (e: Exception) {
            Log.e("DilithiumCrypto", "Init failed: ${e.message}")
            throw RuntimeException("Failed to initialize Dilithium KeyPairGenerator", e)
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
            val kf = KeyFactory.getInstance("Dilithium", bcProvider)
            val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            val signer = Signature.getInstance("Dilithium", bcProvider)
            signer.initSign(privateKey)
            signer.update(data)
            signer.sign()
        } catch (e: Exception) {
            Log.e("DilithiumCrypto", "Sign failed: ${e.message}")
            ByteArray(0)
        }
    }

    override fun verify(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean {
        return try {
            val kf = KeyFactory.getInstance("Dilithium", bcProvider)
            val publicKey = kf.generatePublic(X509EncodedKeySpec(publicKeyBytes))

            val verifier = Signature.getInstance("Dilithium", bcProvider)
            verifier.initVerify(publicKey)
            verifier.update(data)
            verifier.verify(signature)
        } catch (e: Exception) {
            Log.e("DilithiumCrypto", "Verify error: ${e.message}")
            false
        }
    }
}

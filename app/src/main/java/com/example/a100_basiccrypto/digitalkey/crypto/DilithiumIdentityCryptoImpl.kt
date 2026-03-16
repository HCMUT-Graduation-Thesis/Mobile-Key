package com.example.a100_basiccrypto.digitalkey.crypto

import android.util.Log
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Implementation of Dilithium Crypto using the BouncyCastle provider instance directly.
 * This avoids conflicts with Android's built-in (and often outdated/restricted) "BC" provider.
 * The library-provided BouncyCastleProvider is used to ensure PQC algorithm support.
 */
class DilithiumIdentityCryptoImpl : IIdentityCrypto {

    // Use a private instance of the BouncyCastle provider to avoid global registration issues on Android.
    private val bcProvider: Provider = BouncyCastleProvider()
    private val keyPair: KeyPair

    init {
        try {
            // Generate the long-term identity keypair using JCA with the explicit provider instance.
            // Using "Dilithium" or "Dilithium3" depending on provider registration.
            val kpg = KeyPairGenerator.getInstance("Dilithium", bcProvider)
            kpg.initialize(DilithiumParameterSpec.dilithium3, SecureRandom())
            keyPair = kpg.generateKeyPair()
        } catch (e: Exception) {
            Log.e("DilithiumCrypto", "Init failed: ${e.message}")
            // Fallback or rethrow as RuntimeException to match the observed crash but with more info
            throw RuntimeException("Failed to initialize Dilithium KeyPairGenerator: ${e.message}", e)
        }
    }

    /**
     * Returns the RAW 1952 bytes of the Public Key.
     */
    override fun getPublicKey(): ByteArray {
        val encoded = keyPair.public.encoded // X.509 encoded
        return encoded.sliceArray(encoded.size - 1952 until encoded.size)
    }

    /**
     * Returns the RAW 4016 bytes of the Private Key.
     */
    override fun getPrivateKey(): ByteArray {
        val encoded = keyPair.private.encoded // PKCS#8 encoded
        return encoded.sliceArray(encoded.size - 4016 until encoded.size)
    }

    /**
     * Signs data using JCA Signature with the explicit BC provider instance.
     */
    override fun sign(data: ByteArray, privateKeyBytes: ByteArray): ByteArray {
        return try {
            val params = DilithiumPrivateKeyParameters(DilithiumParameters.dilithium3, privateKeyBytes, null)
            val pki: PrivateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(params)
            val kf = KeyFactory.getInstance("Dilithium", bcProvider)
            val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(pki.encoded))

            val signer = Signature.getInstance("Dilithium", bcProvider)
            signer.initSign(privateKey)
            signer.update(data)
            signer.sign()
        } catch (e: Exception) {
            Log.e("DilithiumCrypto", "Sign failed: ${e.message}")
            ByteArray(0)
        }
    }

    /**
     * Verifies signature using JCA Signature.
     */
    override fun verify(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean {
        return try {
            val params = DilithiumPublicKeyParameters(DilithiumParameters.dilithium3, publicKeyBytes)
            val spki: SubjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params)
            val kf = KeyFactory.getInstance("Dilithium", bcProvider)
            val publicKey = kf.generatePublic(X509EncodedKeySpec(spki.encoded))

            val verifier = Signature.getInstance("Dilithium", bcProvider)
            verifier.initVerify(publicKey)
            verifier.update(data)
            val result = verifier.verify(signature)
            
            if (!result) {
                Log.w("DilithiumCrypto", "Verification failed.")
            }
            result
        } catch (e: Exception) {
            Log.e("DilithiumCrypto", "Verify error: ${e.message}")
            false
        }
    }
}

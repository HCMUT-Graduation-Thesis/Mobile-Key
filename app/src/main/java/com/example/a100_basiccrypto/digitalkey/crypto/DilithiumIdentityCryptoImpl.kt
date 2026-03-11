package com.example.a100_basiccrypto.digitalkey.crypto

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import java.security.SecureRandom

class DilithiumIdentityCryptoImpl : IIdentityCrypto {
    
    private val publicKey: DilithiumPublicKeyParameters
    private val privateKey: DilithiumPrivateKeyParameters

    init {
        val random = SecureRandom()
        val keyGen = DilithiumKeyPairGenerator()
        val param = DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3)
        keyGen.init(param)
        val keyPair = keyGen.generateKeyPair()
        publicKey = keyPair.public as DilithiumPublicKeyParameters
        privateKey = keyPair.private as DilithiumPrivateKeyParameters
    }

    override fun getPublicKey(): ByteArray {
        return publicKey.encoded
    }

    override fun getPrivateKey(): ByteArray {
        return privateKey.encoded
    }
}

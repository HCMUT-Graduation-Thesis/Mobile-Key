package com.example.a100_basiccrypto

/**
 * Interface for long-term identity crypto operations.
 * Allows switching between different implementations (e.g., NIST P-256, Ed25519).
 */
interface IIdentityCrypto {
    fun getPublicKey(): ByteArray
    fun getPrivateKey(): String // Returns hex string for current test
}

/**
 * NIST P-256 (secp256r1) implementation of Identity Crypto.
 */
class EccIdentityCryptoImpl : IIdentityCrypto {
    
    companion object {
        // Hardcoded Long PK A from Test Vector
        private const val LONG_PK_A_HEX = "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C37725811805271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
        private const val LONG_SK_A_HEX = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433"
    }

    override fun getPublicKey(): ByteArray {
        return CryptoUtils.run { LONG_PK_A_HEX.hexToBytes() }
    }

    override fun getPrivateKey(): String {
        return LONG_SK_A_HEX
    }
}

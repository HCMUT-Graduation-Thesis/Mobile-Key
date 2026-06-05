package com.example.a100_basiccrypto.data.model

/**
 * Stores the persistent PQC (Dilithium) Identity for a user account.
 */
data class UserIdentity(
    val email: String,
    val publicKey: ByteArray,
    val privateKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as UserIdentity
        return email == other.email &&
                publicKey.contentEquals(other.publicKey) &&
                privateKey.contentEquals(other.privateKey)
    }

    override fun hashCode(): Int {
        var result = email.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        return result
    }
}

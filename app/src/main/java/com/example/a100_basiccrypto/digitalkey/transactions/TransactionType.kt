package com.example.a100_basiccrypto.digitalkey.transactions

/**
 * Supported transaction types in the digital key system.
 */
enum class TransactionType {
    OWNER_PAIRING,
    FRIEND_PAIRING,
    STANDARD,
    FAST
}

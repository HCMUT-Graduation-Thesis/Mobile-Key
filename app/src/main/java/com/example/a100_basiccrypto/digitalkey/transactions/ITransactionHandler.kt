package com.example.a100_basiccrypto.digitalkey.transactions

interface ITransactionHandler {
    fun processCommand(apduCommand: ByteArray): ByteArray
    fun resetTransaction()
    fun isTransactionComplete(): Boolean
}

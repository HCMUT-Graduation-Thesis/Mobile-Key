package com.example.a100_basiccrypto.digitalkey.transactions

interface ITransactionHandler {
    fun processCommand(msgId: Byte, payload: ByteArray): ByteArray
    fun resetTransaction()
    fun isTransactionComplete(): Boolean
}

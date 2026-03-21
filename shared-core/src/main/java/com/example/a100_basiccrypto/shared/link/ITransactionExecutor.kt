package com.example.a100_basiccrypto.shared.link

/**
 * Interface for all Transaction Executors (Master/Vehicle side).
 * Decoupled from physical transport (NFC/BLE).
 */
interface ITransactionExecutor {
    /**
     * Executes the transaction logic using the provided transport layer.
     */
    suspend fun execute(transport: ITransportLayer): Boolean

    /**
     * Returns the name of the transaction for logging/UI.
     */
    fun getTransactionName(): String
}

package com.example.a100_basiccrypto.digitalkey.transactions

/**
 * Common interface for all transaction handlers.
 */
interface ITransactionHandler {
    /**
     * Identifies the type of the transaction (Owner Pairing, Fast Auth, etc.).
     */
    val transactionType: TransactionType

    /**
     * Processes an incoming command payload.
     * @return Response payload to send back to the reader.
     */
    fun processCommand(msgId: Byte, payload: ByteArray): ByteArray
    
    /**
     * Resets any session-specific state in the handler.
     */
    fun resetTransaction()
    
    /**
     * Indicates whether the transaction logic has completed successfully.
     */
    fun isTransactionComplete(): Boolean
}

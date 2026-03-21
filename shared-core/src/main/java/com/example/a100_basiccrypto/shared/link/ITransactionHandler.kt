package com.example.a100_basiccrypto.shared.link

/**
 * Interface for all Transaction Responders (Slave/App side).
 * Handles incoming logical frames and provides responses.
 */
interface ITransactionHandler {
    /**
     * Processes an incoming logical frame.
     * @param frame The received frame [CLASS][INS][LEN][DATA]
     * @return Response raw payload
     */
    fun processCommand(frame: LogicalFrame): ByteArray
    
    /**
     * Resets any session-specific state in the handler.
     */
    fun resetTransaction()
    
    /**
     * Indicates whether the transaction logic has completed successfully.
     */
    fun isTransactionComplete(): Boolean
}

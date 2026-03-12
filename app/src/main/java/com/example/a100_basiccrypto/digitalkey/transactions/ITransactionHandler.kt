package com.example.a100_basiccrypto.digitalkey.transactions

import com.example.a100_basiccrypto.digitalkey.core.LogicalFrame

/**
 * Common interface for all transaction handlers using Logical Frames.
 */
interface ITransactionHandler {
    /**
     * Processes an incoming logical frame.
     * @param frame The received frame [CLASS][INS][LEN][DATA]
     * @return Response raw payload (The Router will wrap it back into a frame)
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

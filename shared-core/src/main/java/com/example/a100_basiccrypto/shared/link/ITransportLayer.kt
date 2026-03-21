package com.example.a100_basiccrypto.shared.link

/**
 * Transport Layer Interface.
 * Handles standardized communication using LogicalFrames across physical mediums (NFC/BLE).
 */
interface ITransportLayer {
    /**
     * Sends a command frame and waits for the complete response frame.
     * Implementation should handle any underlying fragmentation (chaining).
     */
    suspend fun exchange(frame: LogicalFrame): LogicalFrame
}

package com.example.a100_basiccrypto.digitalkey.nfc

/**
 * Interface for communication transports (NFC, BLE).
 */
interface ITransportProvider {
    /**
     * Sends data to the connected reader.
     */
    fun sendData(data: ByteArray)

    /**
     * Called when a full data payload is received from the reader.
     */
    fun onDataReceived(msgId: Byte, payload: ByteArray)

    /**
     * Resets the transport session.
     */
    fun resetTransport()
}

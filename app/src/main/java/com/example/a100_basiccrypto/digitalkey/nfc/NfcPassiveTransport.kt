package com.example.a100_basiccrypto.digitalkey.nfc

import com.example.a100_basiccrypto.shared.link.*
import com.example.a100_basiccrypto.shared.policy.TransportType
import com.example.a100_basiccrypto.shared.physical.NfcConstants

/**
 * NFC Implementation of Passive Transport.
 * Handles APDU chaining and bridges to LogicalFrames.
 */
class NfcPassiveTransport : IPassiveTransport {
    
    override val transportType: TransportType = TransportType.NFC
    private var callback: TransportCallback? = null
    private val chainingManager = NfcChainingManager()

    override fun setCallback(callback: TransportCallback) {
        this.callback = callback
    }

    /**
     * Processes raw APDU and returns raw APDU response.
     * @param onFrameProcessed Callback to notify the service about the result for UI/Logging.
     */
    fun onApduReceived(
        commandApdu: ByteArray, 
        onFrameProcessed: (LogicalFrame, LogicalResponse) -> Unit
    ): ByteArray {
        if (commandApdu.size < 2) return NfcConstants.SW_INTERNAL_ERROR

        val fullPayload = chainingManager.handleIncomingFragment(commandApdu)
        
        return if (fullPayload != null) {
            val cla = commandApdu[0]
            val ins = commandApdu[1]
            val frame = LogicalFrame(cla, ins, fullPayload)
            
            val response = callback?.onFrameReceived(frame, this) 
                ?: LogicalResponse(0x01.toByte()) // General Error

            // Notify the service about the logical result
            onFrameProcessed(frame, response)

            val result = response.serialize()
            
            if (result.size > NfcConstants.MAX_APDU_PAYLOAD_SIZE) {
                chainingManager.setOutgoingBuffer(result)
                chainingManager.getNextOutgoingChunk(0)
            } else {
                if (result.size == 2 && (result[0].toInt() and 0xFF) >= 0x60) {
                    result
                } else {
                    result + NfcConstants.SW_SUCCESS
                }
            }
        } else {
            return NfcConstants.SW_HAS_MORE_DATA
        }
    }

    fun getNextChunk(chunkIndex: Int): ByteArray {
        return chainingManager.getNextOutgoingChunk(chunkIndex)
    }

    fun reset() {
        chainingManager.clear()
        callback?.onConnectionStateChanged(this, false)
    }
}

package com.example.a100_basiccrypto.digitalkey.nfc

import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.digitalkey.nfc.NfcConstants.SW_SUCCESS
import java.io.ByteArrayOutputStream

/**
 * Handles APDU Command Chaining (fragmentation and reassembly).
 */
class NfcChainingManager {

    private var rxBuffer: ByteArrayOutputStream? = null
    private var txBuffer: ByteArray? = null

    /**
     * Collects incoming fragments.
     * @return Full payload if this was the last fragment, null otherwise.
     */
    fun handleIncomingFragment(apdu: ByteArray): ByteArray? {
        val chunkIndex = apdu[2].toInt() and 0xFF
        val isLastChunk = apdu[3].toInt() == 0x01
        val lc = apdu[4].toInt() and 0xFF

        if (chunkIndex == 0) {
            rxBuffer = ByteArrayOutputStream()
        }

        rxBuffer?.write(apdu, 5, lc)

        return if (isLastChunk) {
            val fullData = rxBuffer?.toByteArray()
            rxBuffer = null
            fullData
        } else {
            null
        }
    }

    /**
     * Sets the buffer to be sent back in chunks.
     */
    fun setOutgoingBuffer(data: ByteArray) {
        txBuffer = data
    }

    /**
     * Prepares the next chunk for the Reader to pull.
     */
    fun getNextOutgoingChunk(chunkIndex: Int): ByteArray {
        val buffer = txBuffer ?: return byteArrayOf(0x6F.toByte(), 0x00.toByte()) // Internal Error
        val offset = chunkIndex * MAX_APDU_PAYLOAD_SIZE

        if (offset >= buffer.size) {
            return byteArrayOf(0x6F.toByte(), 0x00.toByte())
        }

        val remaining = buffer.size - offset
        val chunkSize = minOf(remaining, MAX_APDU_PAYLOAD_SIZE)
        val chunk = buffer.sliceArray(offset until offset + chunkSize)

        return if (offset + chunkSize < buffer.size) {
            chunk + SW_HAS_MORE_DATA
        } else {
            txBuffer = null
            chunk + SW_SUCCESS
        }
    }
    
    fun clear() {
        rxBuffer = null
        txBuffer = null
    }
}

package com.example.a100_basiccrypto.digitalkey.nfc

import com.example.a100_basiccrypto.shared.physical.NfcConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_SUCCESS
import com.example.a100_basiccrypto.shared.link.PayloadChainer

/**
 * Android-specific wrapper for PayloadChainer, handling NFC APDU semantics.
 * Used by HostApduService (HCE) to manage fragmented communication.
 */
class NfcChainingManager {

    private val chainer = PayloadChainer(MAX_APDU_PAYLOAD_SIZE)

    /**
     * Collects incoming fragments from Command APDUs.
     */
    fun handleIncomingFragment(apdu: ByteArray): ByteArray? {
        if (apdu.size < 5) return apdu 

        val chunkIndex = apdu[2].toInt() and 0xFF
        val isLastChunk = apdu[3].toInt() == 0x01
        val lc = apdu[4].toInt() and 0xFF
        
        if (apdu.size < 5 + lc) return apdu

        // If it's the first chunk, ensure the chainer is clean
        if (chunkIndex == 0) chainer.reset()

        val payloadFragment = apdu.sliceArray(5 until 5 + lc)
        return chainer.append(payloadFragment, isLastChunk)
    }

    /**
     * Sets the full data to be sent back to the Reader.
     */
    fun setOutgoingBuffer(data: ByteArray) {
        chainer.setOutgoingBuffer(data)
    }

    /**
     * Retrieves the next Response APDU chunk for the Reader.
     */
    fun getNextOutgoingChunk(chunkIndex: Int): ByteArray {
        val chunk = chainer.getChunk(chunkIndex) 
            ?: return byteArrayOf(0x6F.toByte(), 0x01.toByte()) // Error: Not Found

        val hasMore = chainer.hasMoreChunks(chunkIndex)
        
        return if (hasMore) {
            chunk + SW_HAS_MORE_DATA
        } else {
            val result = chunk + SW_SUCCESS
            chainer.reset() // Clear after last chunk sent
            result
        }
    }
    
    fun clear() {
        chainer.reset()
    }
}

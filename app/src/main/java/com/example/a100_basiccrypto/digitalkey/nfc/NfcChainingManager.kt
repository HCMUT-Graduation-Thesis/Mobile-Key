package com.example.a100_basiccrypto.digitalkey.nfc

import com.example.a100_basiccrypto.shared.physical.NfcConstants.MAX_APDU_PAYLOAD_SIZE
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_HAS_MORE_DATA
import com.example.a100_basiccrypto.shared.physical.NfcConstants.SW_SUCCESS
import java.io.ByteArrayOutputStream

/**
 * Handles APDU Command Chaining (fragmentation and reassembly).
 */
class NfcChainingManager {

    private var rxBuffer: ByteArrayOutputStream? = null
    private var txBuffer: ByteArray? = null

    /**
     * Collects incoming fragments.
     */
    fun handleIncomingFragment(apdu: ByteArray): ByteArray? {
        if (apdu.size < 5) return apdu 

        val chunkIndex = apdu[2].toInt() and 0xFF
        val isLastChunk = apdu[3].toInt() == 0x01
        val lc = apdu[4].toInt() and 0xFF
        
        if (apdu.size < 5 + lc) return apdu

        if (chunkIndex == 0) rxBuffer = ByteArrayOutputStream()
        rxBuffer?.write(apdu, 5, lc)

        return if (isLastChunk) {
            val data = rxBuffer?.toByteArray()
            rxBuffer = null
            data
        } else null
    }

    fun setOutgoingBuffer(data: ByteArray) {
        txBuffer = data
    }

    fun getNextOutgoingChunk(chunkIndex: Int): ByteArray {
        val buffer = txBuffer ?: return byteArrayOf(0x6F.toByte(), 0x01.toByte())
        val offset = chunkIndex * MAX_APDU_PAYLOAD_SIZE

        if (offset >= buffer.size) {
            txBuffer = null 
            return byteArrayOf(0x6F.toByte(), 0x02.toByte())
        }

        val remaining = buffer.size - offset
        val chunkSize = if (remaining < MAX_APDU_PAYLOAD_SIZE) remaining else MAX_APDU_PAYLOAD_SIZE
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

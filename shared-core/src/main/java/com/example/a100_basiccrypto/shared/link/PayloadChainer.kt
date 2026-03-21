package com.example.a100_basiccrypto.shared.link

import java.io.ByteArrayOutputStream

/**
 * Core logic for fragmenting and reassembling large payloads.
 * This is transport-agnostic and can be used for NFC, BLE, or any 
 * byte-oriented communication.
 */
class PayloadChainer(private val maxChunkSize: Int) {

        private var rxBuffer = ByteArrayOutputStream()
        private var txBuffer: ByteArray? = null

    /**
     * Splits a large payload into smaller fragments.
     */
    fun fragment(data: ByteArray): List<ByteArray> {
        val fragments = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + maxChunkSize, data.size)
            fragments.add(data.sliceArray(offset until end))
            offset += maxChunkSize
        }
        return fragments
    }

    /**
     * Collects and assembles incoming fragments.
     * @param fragment The incoming byte array chunk.
     * @param isLast True if this is the final fragment.
     * @return The complete byte array if assembly is finished, otherwise null.
     */
    fun append(fragment: ByteArray, isLast: Boolean): ByteArray? {
        rxBuffer.write(fragment)
        return if (isLast) {
            val fullData = rxBuffer.toByteArray()
            rxBuffer.reset()
            fullData
        } else null
    }

    /**
     * Helper for sequential reading of a pre-set buffer.
     */
    fun setOutgoingBuffer(data: ByteArray) {
        txBuffer = data
    }

    fun getChunk(index: Int): ByteArray? {
        val buffer = txBuffer ?: return null
        val offset = index * maxChunkSize
        if (offset >= buffer.size) return null

        val remaining = buffer.size - offset
        val size = if (remaining < maxChunkSize) remaining else maxChunkSize
        return buffer.sliceArray(offset until offset + size)
    }

    fun hasMoreChunks(currentIndex: Int): Boolean {
        val buffer = txBuffer ?: return false
        return (currentIndex + 1) * maxChunkSize < buffer.size
    }

    /**
     * Clears internal state.
     */
    fun reset() {
        rxBuffer.reset()
        txBuffer = null
    }
}

package com.example.a100_basiccrypto.shared.link

import java.nio.ByteBuffer

/**
 * Represents a Transport-Agnostic logical command frame.
 * Format: [CLASS (1b)] [INS (1b)] [LENGTH (2b)] [DATA (Nb)]
 */
data class LogicalFrame(
    val msgClass: Byte,
    val msgId: Byte,
    val payload: ByteArray
) {
    /**
     * Serializes the frame into a byte array for transport.
     */
    fun serialize(): ByteArray {
        val buffer = ByteBuffer.allocate(4 + payload.size)
        buffer.put(msgClass)
        buffer.put(msgId)
        buffer.putShort(payload.size.toShort())
        buffer.put(payload)
        return buffer.array()
    }

    companion object {
        /**
         * Deserializes a raw byte array into a LogicalFrame.
         */
        fun deserialize(data: ByteArray): LogicalFrame? {
            if (data.size < 4) return null
            val buffer = ByteBuffer.wrap(data)
            val msgClass = buffer.get()
            val msgId = buffer.get()
            val length = buffer.short.toInt() and 0xFFFF
            
            if (buffer.remaining() < length) return null
            
            val payload = ByteArray(length)
            buffer.get(payload)
            
            return LogicalFrame(msgClass, msgId, payload)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as LogicalFrame
        if (msgClass != other.msgClass) return false
        if (msgId != other.msgId) return false
        return payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = msgClass.toInt()
        result = 31 * result + msgId.toInt()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

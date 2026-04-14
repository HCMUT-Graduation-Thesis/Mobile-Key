package com.example.a100_basiccrypto.digitalkey.ble

import android.util.Log
import com.example.a100_basiccrypto.shared.link.IActiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.PayloadChainer
import com.example.a100_basiccrypto.shared.policy.TransportType
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Implementation of IActiveTransport for BLE L2CAP.
 * Optimized: Uses LITTLE_ENDIAN for headers to match project standards.
 */
class L2capActiveTransport(
    private val bleCentralManager: BleCentralManager
) : IActiveTransport {

    companion object {
        private const val TAG = "L2capTransport"
    }

    private val chainer = PayloadChainer(1024)
    private var responseDeferred: CompletableDeferred<LogicalResponse>? = null
    private val exchangeMutex = Mutex()

    // Persistent buffer to handle stream data across multiple callbacks
    private var rxStreamBuffer = ByteArrayOutputStream()

    override val transportType: TransportType = TransportType.BLE

    override suspend fun exchange(frame: LogicalFrame): LogicalResponse {
        return exchangeMutex.withLock {
            // Build single packet framing using LITTLE_ENDIAN
            val header = ByteBuffer.allocate(5).apply {
                order(ByteOrder.LITTLE_ENDIAN)
                put(frame.msgClass)
                put(frame.msgId)
                put(0x01.toByte()) // Marking as final packet
                putShort(frame.payload.size.toShort())
            }.array()
            
            val packet = header + frame.payload
            Log.d(TAG, ">>> SENDING: Class=0x%02X, INS=0x%02X, Len=%d (LE)".format(
                frame.msgClass, frame.msgId, frame.payload.size
            ))
            
            val waiter = CompletableDeferred<LogicalResponse>()
            responseDeferred = waiter
            
            // Write entire payload to stream. Flow control is handled by L2CAP Credits.
            bleCentralManager.sendData(packet)
            
            try {
                return withTimeout(15000) { waiter.await() }
            } catch (e: Exception) {
                Log.e(TAG, "L2CAP Exchange failed/timeout: ${e.message}")
                return LogicalResponse(0xE0.toByte())
            } finally {
                responseDeferred = null
                chainer.reset()
            }
        }
    }

    /**
     * Handles incoming raw bytes from L2CAP socket.
     * Implements a state-machine like loop to extract full packets from the stream.
     */
    fun handleIncomingData(data: ByteArray) {
        synchronized(rxStreamBuffer) {
            rxStreamBuffer.write(data)
            processStream()
        }
    }

    private fun processStream() {
        var currentData = rxStreamBuffer.toByteArray()
        
        while (currentData.size >= 4) {
            // Read header using LITTLE_ENDIAN
            val buffer = ByteBuffer.wrap(currentData).order(ByteOrder.LITTLE_ENDIAN)
            val status = buffer.get()
            val control = buffer.get()
            val length = buffer.short.toInt() and 0xFFFF
            
            val totalPacketSize = 4 + length
            if (currentData.size < totalPacketSize) {
                // Wait for more data to arrive
                return
            }

            // Extract the full chunk
            val payload = currentData.sliceArray(4 until totalPacketSize)
            
            // Clean processed data from the buffer
            val remainingData = currentData.sliceArray(totalPacketSize until currentData.size)
            rxStreamBuffer.reset()
            rxStreamBuffer.write(remainingData)
            currentData = remainingData

            Log.d(TAG, "<<< RECEIVED: Status=0x%02X, Ctrl=0x%02X, Len=%d (LE)".format(status, control, length))

            // Logic handling
            if (status == 0xA0.toByte() && length == 0) {
                // Ignore pure ACKs if vehicle still sends them
                continue
            } else {
                val isLast = (control == 0x01.toByte())
                // Still use chainer to assemble in case vehicle sends in chunks
                val assembledData = chainer.append(payload, isLast)
                
                if (assembledData != null) {
                    responseDeferred?.complete(LogicalResponse(status, assembledData))
                }
                // No manual ACK 0xA0 sent back; L2CAP handles flow control
            }
        }
    }
}

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

/**
 * Implementation of IActiveTransport for BLE L2CAP.
 * Fixed: Added Stream Buffering to handle partial packet arrival.
 */
class L2capActiveTransport(
    private val bleCentralManager: BleCentralManager
) : IActiveTransport {

    companion object {
        private const val TAG = "L2capTransport"
    }

    private val chainer = PayloadChainer(1024)
    private var responseDeferred: CompletableDeferred<LogicalResponse>? = null
    private var ackDeferred: CompletableDeferred<Byte>? = null
    private val exchangeMutex = Mutex()

    // Persistent buffer to handle stream data across multiple callbacks
    private var rxStreamBuffer = ByteArrayOutputStream()

    override val transportType: TransportType = TransportType.BLE

    override suspend fun exchange(frame: LogicalFrame): LogicalResponse {
        return exchangeMutex.withLock {
            val chunks = if (frame.payload.isEmpty()) listOf(byteArrayOf()) else chainer.fragment(frame.payload)
            Log.d(TAG, ">>> START EXCHANGE: Class=0x%02X, INS=0x%02X, Chunks=%d".format(frame.msgClass, frame.msgId, chunks.size))
            
            for (i in chunks.indices) {
                val chunk = chunks[i]
                val isLast = (i == chunks.size - 1)
                
                val header = ByteBuffer.allocate(5).apply {
                    put(frame.msgClass)
                    put(frame.msgId)
                    put(if (isLast) 0x01.toByte() else 0x00.toByte())
                    putShort(chunk.size.toShort())
                }.array()
                
                val packet = header + chunk
                
                if (!isLast) {
                    val waiter = CompletableDeferred<Byte>()
                    ackDeferred = waiter
                    bleCentralManager.sendData(packet)
                    
                    try {
                        withTimeout(3000) {
                            val ackStatus = waiter.await()
                            if (ackStatus != 0xA0.toByte()) throw Exception("Invalid ACK")
                        }
                    } catch (e: Exception) {
                        return LogicalResponse(0xE0.toByte())
                    } finally {
                        ackDeferred = null
                    }
                } else {
                    val waiter = CompletableDeferred<LogicalResponse>()
                    responseDeferred = waiter
                    bleCentralManager.sendData(packet)
                    
                    try {
                        val response = withTimeout(15000) { waiter.await() }
                        Log.d(TAG, "<<< EXCHANGE COMPLETE: Status=0x%02X, DataLen=%d".format(response.status, response.data.size))
                        return response
                    } catch (e: Exception) {
                        Log.e(TAG, "Exchange Timeout/Error: ${e.message}")
                        return LogicalResponse(0xE0.toByte())
                    } finally {
                        responseDeferred = null
                        chainer.reset()
                    }
                }
            }
            LogicalResponse(0xE0.toByte())
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
            val buffer = ByteBuffer.wrap(currentData)
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

            Log.v(TAG, "<<< PARSED PACKET: Status=0x%02X, Control=0x%02X, Len=%d".format(status, control, length))

            // Logic handling
            if (status == 0xA0.toByte() && length == 0) {
                ackDeferred?.complete(status)
            } else {
                val isLast = (control == 0x01.toByte())
                val assembledData = chainer.append(payload, isLast)
                
                if (assembledData != null) {
                    responseDeferred?.complete(LogicalResponse(status, assembledData))
                } else if (!isLast) {
                    val ack = byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())
                    bleCentralManager.sendData(ack)
                }
            }
        }
    }
}

package com.example.a100_basiccrypto.digitalkey.ble

import com.example.a100_basiccrypto.shared.link.IActiveTransport
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.policy.TransportType
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout

/**
 * Implementation of IActiveTransport for BLE L2CAP.
 * Bridges the BleCentralManager with Transaction Executors.
 */
class L2capActiveTransport(
    private val bleCentralManager: BleCentralManager
) : IActiveTransport {

    private var responseDeferred: CompletableDeferred<LogicalResponse>? = null
    private val exchangeMutex = Mutex()

    override val transportType: TransportType = TransportType.BLE

    override suspend fun exchange(frame: LogicalFrame): LogicalResponse {
        // Ensure only one transaction (Control or Telemetry) happens at a time
        return exchangeMutex.withLock {
            val payload = frame.serialize()
            val deferred = CompletableDeferred<LogicalResponse>()
            responseDeferred = deferred
            
            // Send via Central Manager
            bleCentralManager.sendData(payload)
            
            // Wait for response with a 5-second timeout
            try {
                withTimeout(5000) {
                    deferred.await()
                }
            } catch (e: Exception) {
                LogicalResponse(0xE0.toByte()) // Status.ERR_GENERAL
            } finally {
                responseDeferred = null
            }
        }
    }

    /**
     * Called by BleCentralManager when raw Rx data is received from the Socket.
     */
    fun handleIncomingData(data: ByteArray) {
        try {
            val response = LogicalResponse.deserialize(data)
            responseDeferred?.complete(response)
        } catch (e: Exception) {
            // Handle parsing error
        }
    }
}

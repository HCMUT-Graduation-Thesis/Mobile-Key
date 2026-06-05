package com.example.a100_basiccrypto.ui.keycontrol

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransactionClient
import com.example.a100_basiccrypto.digitalkey.transactions.StandardTransactionClient
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.IIdentityCrypto
import com.example.a100_basiccrypto.shared.model.VehicleStatus
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

class ControlViewModel(
    private val storageManager: SecureKeyStorageManager,
    private val identityCrypto: IIdentityCrypto
) : ViewModel() {

    private val fastTxClient = FastTransactionClient(storageManager) { Log.d("ControlVM", "FastTx: $it") }
    private val standardTxClient = StandardTransactionClient(storageManager, identityCrypto) { Log.d("ControlVM", "StandardTx: $it") }

    private val _uiState = MutableStateFlow<ControlUiState>(ControlUiState.Idle)
    val uiState: StateFlow<ControlUiState> = _uiState

    private val _events = MutableSharedFlow<ControlEvent>()
    val events: SharedFlow<ControlEvent> = _events.asSharedFlow()

    private val _vehicleStatus = MutableStateFlow<VehicleStatus?>(null)
    val vehicleStatus: StateFlow<VehicleStatus?> = _vehicleStatus

    private val telemetryListener: (VehicleStatus) -> Unit = { status ->
        _vehicleStatus.value = status
    }

    init {
        BleProvider.addTelemetryListener(telemetryListener)
    }

    fun executeAction(keyID: ByteArray, msgClass: Byte, targetIns: Byte) {
        val transport = BleProvider.getTransport()
        if (transport == null || BleProvider.getManager()?.isConnected() != true) {
            viewModelScope.launch { _events.emit(ControlEvent.Error("BLE not connected.")) }
            return
        }

        viewModelScope.launch {
            _uiState.value = ControlUiState.Loading
            
            // 1. Attempt Fast Transaction
            val status = fastTxClient.execute(transport, keyID, msgClass, targetIns)

            when (status) {
                Status.SUCCESS -> {
                    _uiState.value = ControlUiState.Idle
                    _events.emit(ControlEvent.ActionSuccess("Action executed successfully over BLE."))
                }
                
                Status.ERR_REPLAY_ATTACK, Status.ERR_AUTH_FAIL -> {
                    // 2. HSR: Trigger Standard Sync
                    Log.w("ControlVM", "Security issue (0x%02X). Starting HSR...".format(status))
                    val syncSuccess = standardTxClient.executeSync(transport, keyID)

                    if (syncSuccess) {
                        delay(1000)
                        // 3. Retry original command
                        val retryStatus = fastTxClient.execute(transport, keyID, msgClass, targetIns)
                        _uiState.value = ControlUiState.Idle
                        if (retryStatus == Status.SUCCESS) {
                            _events.emit(ControlEvent.ActionSuccess("Security Restored & Action Executed!"))
                        } else {
                            _events.emit(ControlEvent.Error("Security Restored, but command failed (0x%02X).".format(retryStatus)))
                        }
                    } else {
                        _uiState.value = ControlUiState.Idle
                        _events.emit(ControlEvent.ShowNfcRecovery)
                    }
                }
                
                else -> {
                    _uiState.value = ControlUiState.Idle
                    _events.emit(ControlEvent.Error("Vehicle returned error code: 0x%02X".format(status)))
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        BleProvider.removeTelemetryListener(telemetryListener)
    }

    sealed class ControlUiState {
        object Idle : ControlUiState()
        object Loading : ControlUiState()
    }

    sealed class ControlEvent {
        data class ActionSuccess(val message: String) : ControlEvent()
        data class Error(val message: String) : ControlEvent()
        object ShowNfcRecovery : ControlEvent()
    }
}

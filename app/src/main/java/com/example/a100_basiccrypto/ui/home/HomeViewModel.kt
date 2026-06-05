package com.example.a100_basiccrypto.ui.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.NotificationStore
import com.example.a100_basiccrypto.data.repository.AuthRepository
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.model.KeyState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class HomeViewModel(
    private val storageManager: SecureKeyStorageManager,
    private val authRepository: AuthRepository
) : ViewModel() {

    private val _keys = MutableStateFlow<List<DigitalKeyRecord>>(emptyList())
    val keys: StateFlow<List<DigitalKeyRecord>> = _keys

    private val _bleStatus = MutableStateFlow("Status: Initializing...")
    val bleStatus: StateFlow<String> = _bleStatus

    private val _isL2capConnected = MutableStateFlow(false)
    val isL2capConnected: StateFlow<Boolean> = _isL2capConnected

    private val _unreadBadgeVisible = NotificationStore.unreadBadgeVisible
    val unreadBadgeVisible: StateFlow<Boolean> = _unreadBadgeVisible

    init {
        observeBleProvider()
    }

    private fun observeBleProvider() {
        viewModelScope.launch {
            BleProvider.addStatusListener { status ->
                _bleStatus.value = "Status: $status"
            }
        }
        viewModelScope.launch {
            BleProvider.addConnectionStateListener { isConnected ->
                _isL2capConnected.value = isConnected
            }
        }
    }

    fun refreshKeys(email: String) {
        val visibleKeys = storageManager.getAllKeys().filter {
            it.accountEmail == email && 
            (it.core.keyState == KeyState.ACTIVE || it.core.keyState == KeyState.PROVISIONING) 
        }
        _keys.value = visibleKeys
    }

    fun logout() {
        authRepository.logout()
        BleProvider.logoutAndCleanup()
    }

    fun setOnline() {
        authRepository.setOnline()
    }
}

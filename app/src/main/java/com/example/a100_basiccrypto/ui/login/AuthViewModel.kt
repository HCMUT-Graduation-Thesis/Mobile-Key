package com.example.a100_basiccrypto.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.data.repository.AuthRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

class AuthViewModel(
    private val authRepository: AuthRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow<AuthUiState>(AuthUiState.Idle)
    val uiState: StateFlow<AuthUiState> = _uiState

    private val _events = MutableSharedFlow<AuthEvent>()
    val events: SharedFlow<AuthEvent> = _events.asSharedFlow()

    fun login(email: String, pass: String) {
        viewModelScope.launch {
            _uiState.value = AuthUiState.Loading
            val success = authRepository.login(email, pass)
            _uiState.value = AuthUiState.Idle
            if (success) {
                _events.emit(AuthEvent.LoginSuccess)
            } else {
                _events.emit(AuthEvent.Error("Invalid credentials or user not found"))
            }
        }
    }

    fun register(email: String, pass: String, displayName: String = "") {
        viewModelScope.launch {
            _uiState.value = AuthUiState.Loading
            val success = authRepository.register(email, pass, displayName)
            _uiState.value = AuthUiState.Idle
            if (success) {
                _events.emit(AuthEvent.RegisterSuccess)
            } else {
                _events.emit(AuthEvent.Error("Email already exists"))
            }
        }
    }

    sealed class AuthUiState {
        object Idle : AuthUiState()
        object Loading : AuthUiState()
    }

    sealed class AuthEvent {
        object LoginSuccess : AuthEvent()
        object RegisterSuccess : AuthEvent()
        data class Error(val message: String) : AuthEvent()
    }
}

package com.example.a100_basiccrypto.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.a100_basiccrypto.data.repository.AuthRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AuthViewModel(private val repository: AuthRepository) : ViewModel() {

    private val _loginState = MutableStateFlow<LoginState>(LoginState.Idle)
    val loginState = _loginState.asStateFlow()

    private val _events = MutableSharedFlow<AuthEvent>()
    val events = _events.asSharedFlow()

    fun login(email: String, pass: String) {
        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            val success = repository.login(email, pass)
            if (success) {
                _loginState.value = LoginState.Success
                _events.emit(AuthEvent.NavigateToHome)
            } else {
                _loginState.value = LoginState.Error("Invalid email, password or device unauthorized.")
            }
        }
    }

    /**
     * Checks if user is already logged in (Offline-First).
     * If logged in, tries a background refresh.
     */
    fun checkAutoLogin() {
        viewModelScope.launch {
            val isSessionValid = repository.checkSessionAndRefresh()
            if (isSessionValid) {
                _events.emit(AuthEvent.NavigateToHome)
            }
        }
    }

    sealed class LoginState {
        object Idle : LoginState()
        object Loading : LoginState()
        object Success : LoginState()
        data class Error(val message: String) : LoginState()
    }

    sealed class AuthEvent {
        object NavigateToHome : AuthEvent()
    }
}

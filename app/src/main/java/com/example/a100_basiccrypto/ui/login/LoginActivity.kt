package com.example.a100_basiccrypto.ui.login

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.MainApplication
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.ui.home.HomeActivity
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {

    private lateinit var etEmail: TextInputEditText
    private lateinit var etPassword: TextInputEditText
    private lateinit var btnLogin: Button
    private lateinit var btnRegister: Button
    private lateinit var progressBar: ProgressBar

    private lateinit var viewModel: AuthViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        initViewModel()
        initViews()
        setupListeners()
        observeViewModel()
    }

    private fun initViewModel() {
        val container = (application as MainApplication).container
        viewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return AuthViewModel(container.authRepository) as T
            }
        })[AuthViewModel::class.java]
    }

    private fun initViews() {
        etEmail = findViewById(R.id.et_login_email)
        etPassword = findViewById(R.id.et_login_password)
        btnLogin = findViewById(R.id.btn_login_action)
        btnRegister = findViewById(R.id.btn_register_action)
        progressBar = findViewById(R.id.pb_login_loading)
    }

    private fun setupListeners() {
        // 1. Check Auto-Login (Offline-First)
        viewModel.checkAutoLogin()

        btnLogin.setOnClickListener { handleLogin() }
        btnRegister.setOnClickListener { handleRegister() }
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            viewModel.loginState.collectLatest { state ->
                setLoading(state is AuthViewModel.LoginState.Loading)
                if (state is AuthViewModel.LoginState.Error) {
                    Toast.makeText(this@LoginActivity, state.message, Toast.LENGTH_SHORT).show()
                }
            }
        }

        lifecycleScope.launch {
            viewModel.events.collect { event ->
                when (event) {
                    AuthViewModel.AuthEvent.NavigateToHome -> {
                        startActivity(Intent(this@LoginActivity, HomeActivity::class.java))
                        finish()
                    }
                }
            }
        }
    }

    private fun handleLogin() {
        val email = etEmail.text.toString()
        val pass = etPassword.text.toString()
        if (email.isBlank() || pass.isBlank()) {
            Toast.makeText(this, "Please enter email and password", Toast.LENGTH_SHORT).show()
            return
        }
        viewModel.login(email, pass)
    }

    private fun handleRegister() {
        // As per new requirement: Registration is disabled or handled by Admin.
        // For now, we just show a message.
        Toast.makeText(this, "Registration is managed by Administrator.", Toast.LENGTH_LONG).show()
    }

    private fun setLoading(isLoading: Boolean) {
        progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
        btnLogin.isEnabled = !isLoading
        btnRegister.isEnabled = !isLoading
    }
}

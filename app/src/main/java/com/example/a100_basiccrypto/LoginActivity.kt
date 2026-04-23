package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.digitalkey.core.MockKeyServer
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {

    private lateinit var etEmail: TextInputEditText
    private lateinit var etPassword: TextInputEditText
    private lateinit var btnLogin: Button
    private lateinit var btnRegister: Button
    private lateinit var progressBar: ProgressBar
    
    private val authManager by lazy { AuthManager(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        initViews()
        setupListeners()
    }

    private fun initViews() {
        etEmail = findViewById(R.id.et_login_email)
        etPassword = findViewById(R.id.et_login_password)
        btnLogin = findViewById(R.id.btn_login_action)
        btnRegister = findViewById(R.id.btn_register_action)
        progressBar = findViewById(R.id.pb_login_loading)
    }

    private fun setupListeners() {
        btnLogin.setOnClickListener { handleLogin() }
        btnRegister.setOnClickListener { handleRegister() }
    }

    private fun handleLogin() {
        val email = etEmail.text.toString()
        val pass = etPassword.text.toString()

        if (email.isEmpty() || pass.isEmpty()) {
            Toast.makeText(this, "Please enter email and password", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            setLoading(true)
            val profile = MockKeyServer.login(email, pass)
            setLoading(false)

            if (profile != null) {
                authManager.saveSession(profile)
                startActivity(Intent(this@LoginActivity, HomeActivity::class.java))
                finish()
            } else {
                Toast.makeText(this@LoginActivity, "Invalid credentials or user not found", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun handleRegister() {
        val email = etEmail.text.toString()
        val pass = etPassword.text.toString()

        if (email.isEmpty() || pass.length < 6) {
            Toast.makeText(this, "Email is required and Password >= 6 chars", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            setLoading(true)
            val success = MockKeyServer.register(email, pass)
            setLoading(false)

            if (success) {
                Toast.makeText(this@LoginActivity, "Account created! You can now login.", Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this@LoginActivity, "Email already exists", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun setLoading(isLoading: Boolean) {
        progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
        btnLogin.isEnabled = !isLoading
        btnRegister.isEnabled = !isLoading
    }
}

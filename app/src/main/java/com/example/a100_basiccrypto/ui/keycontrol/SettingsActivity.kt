package com.example.a100_basiccrypto.ui.keycontrol

import android.os.Bundle
import android.view.LayoutInflater
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.MainApplication
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class SettingsActivity : AppCompatActivity() {

    private lateinit var etVehicleName: TextInputEditText
    private lateinit var tvKeyId: TextView
    private lateinit var tvModuleId: TextView
    private lateinit var btnUpdate: MaterialButton
    private lateinit var btnRevokeOwner: MaterialButton

    private val container by lazy { (application as MainApplication).container }
    private val storageManager by lazy { container.storageManager }
    private val authManager by lazy { container.authManager }
    
    private lateinit var sharingViewModel: SharingViewModel
    
    private var currentKey: DigitalKeyRecord? = null
    private var loadingDialog: AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(
                    container.identityCrypto,
                    storageManager,
                    authManager,
                    container.authRepository,
                    container.keyRepository
                ) as T
            }
        })[SharingViewModel::class.java]

        val keyId = intent.getByteArrayExtra("KEY_ID")
        currentKey = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(keyId) == true }

        if (currentKey == null) {
            finish()
            return
        }

        setupUI()
        observeViewModel()
    }

    private fun setupUI() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_settings)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        etVehicleName = findViewById(R.id.et_settings_vehicle_name)
        tvKeyId = findViewById(R.id.tv_settings_key_id)
        tvModuleId = findViewById(R.id.tv_settings_module_id)
        btnUpdate = findViewById(R.id.btn_settings_firmware_update)
        btnRevokeOwner = findViewById(R.id.btn_settings_revoke_owner)

        currentKey?.let {
            etVehicleName.setText(it.friendlyName.ifEmpty { it.carMetadata?.modelName ?: "Vehicle" })
            tvKeyId.text = "KeyID: ${it.core.keyID?.toHex() ?: "N/A"}"
            tvModuleId.text = "ModuleID: ${it.moduleID?.toHex() ?: "N/A"}"
        }

        btnUpdate.setOnClickListener {
            Toast.makeText(this, "Executing UPDATE_FIRMWARE command...", Toast.LENGTH_SHORT).show()
        }

        btnRevokeOwner.setOnClickListener {
            showPasswordAuthDialog()
        }
    }

    private fun showPasswordAuthDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_password_auth, null)
        val etPassword = dialogView.findViewById<TextInputEditText>(R.id.et_auth_password)

        AlertDialog.Builder(this)
            .setTitle("Confirm Identity")
            .setMessage("Please enter your account password to proceed with vehicle reset.")
            .setView(dialogView)
            .setPositiveButton("VERIFY") { _, _ ->
                val password = etPassword.text.toString()
                if (password.isNotEmpty()) {
                    currentKey?.let { sharingViewModel.revokeOwnerSelf(it, password) }
                } else {
                    Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("CANCEL", null)
            .show()
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            sharingViewModel.uiState.collectLatest { state ->
                when (state) {
                    is SharingViewModel.SharingUiState.Loading -> {
                        showLoadingOverlay("Executing Reset... Please stay near and keep BLE connected.")
                    }
                    is SharingViewModel.SharingUiState.RevokeSuccess -> {
                        hideLoadingOverlay()
                        Toast.makeText(this@SettingsActivity, "Vehicle reset and key deleted successfully.", Toast.LENGTH_LONG).show()
                        finish()
                    }
                    is SharingViewModel.SharingUiState.Error -> {
                        hideLoadingOverlay()
                        showErrorDialog(state.message)
                    }
                    else -> hideLoadingOverlay()
                }
            }
        }
    }

    private fun showLoadingOverlay(message: String) {
        if (loadingDialog == null) {
            val view = LayoutInflater.from(this).inflate(R.layout.dialog_loading_blocking, null)
            view.findViewById<TextView>(R.id.tv_loading_message).text = message
            loadingDialog = AlertDialog.Builder(this)
                .setView(view)
                .setCancelable(false)
                .create()
        } else {
            loadingDialog?.findViewById<TextView>(R.id.tv_loading_message)?.text = message
        }
        if (loadingDialog?.isShowing == false) {
            loadingDialog?.show()
        }
    }

    private fun hideLoadingOverlay() {
        loadingDialog?.dismiss()
        loadingDialog = null
    }

    private fun showErrorDialog(message: String) {
        AlertDialog.Builder(this)
            .setTitle("Execution Failed")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }
}
